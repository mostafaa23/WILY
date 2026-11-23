"""Tests for the bootstrapped dataset builder (risk/ml/dataset.py) and the
offline secret-source collection in ml/build_dataset.py.

None of these need scikit-learn: the dataset layer is dependency-light on
purpose, so labeling and feature-row assembly are testable without the [ml]
extra installed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from wily.risk.ml.dataset import (
    FP_LABEL,
    VALID_LABEL,
    dataset_summary,
    finding_to_row,
    label_findings,
    make_path_labeler,
    read_dataset,
    write_dataset,
)
from wily.risk.ml.dedup import finding_hash_key
from wily.risk.ml.features import FEATURE_NAMES
from wily.scanners.base import Finding

_REPO = Path(__file__).resolve().parent.parent


def _finding(asset: str, category: str = "authz-bypass-missing-authorizer", **ev) -> Finding:
    return Finding(
        asset=asset,
        category=category,
        severity="critical",
        confidence=0.9,
        evidence=dict(ev),
        discovery_source="scanner",
    )


def test_path_labeler_valid_fp_and_skip():
    labeler = make_path_labeler({"/real": True, "/fake": False})
    assert labeler(_finding("https://h/real")) == VALID_LABEL
    assert labeler(_finding("https://h/fake")) == FP_LABEL
    assert labeler(_finding("https://h/unknown")) is None  # no ground truth -> skip


def test_label_findings_skips_unlabeled():
    labeler = make_path_labeler({"/real": True})
    rows = label_findings(
        [_finding("https://h/real"), _finding("https://h/unknown")], labeler, "t"
    )
    assert len(rows) == 1
    assert rows[0]["label"] == 1
    assert rows[0]["label_name"] == VALID_LABEL
    assert rows[0]["source"] == "t"


def test_feedback_overrides_ground_truth():
    f = _finding("https://h/real")
    labeler = make_path_labeler({"/real": True})  # ground truth says VALID
    feedback = {finding_hash_key(f): FP_LABEL}    # analyst overrules: it's an FP
    rows = label_findings([f], labeler, "t", feedback=feedback)
    assert rows[0]["label_name"] == FP_LABEL
    assert rows[0]["source"] == "t+feedback"


def test_row_has_all_features_plus_provenance_and_no_leakage():
    row = finding_to_row(_finding("https://h/real"), VALID_LABEL, "t")
    for name in FEATURE_NAMES:
        assert name in row
    for prov in ("label", "label_name", "category", "asset", "source"):
        assert prov in row
    # The label must NOT be derivable from a feature column: no feature named
    # after the verdict, and feedback_verdict never becomes a feature.
    assert not any("label" in name or "verdict" in name for name in FEATURE_NAMES)


def test_label_does_not_depend_on_evidence_feedback_verdict():
    """Two findings identical except for a planted evidence['feedback_verdict']
    produce identical FEATURE columns - the verdict is the label, not a feature."""
    a = _finding("https://h/real", feedback_verdict="valid")
    b = _finding("https://h/real", feedback_verdict="false_positive")
    ra = finding_to_row(a, VALID_LABEL, "t")
    rb = finding_to_row(b, VALID_LABEL, "t")
    assert [ra[n] for n in FEATURE_NAMES] == [rb[n] for n in FEATURE_NAMES]


def test_write_read_roundtrip_is_deterministic(tmp_path):
    rows = label_findings(
        [_finding("https://h/real"), _finding("https://h/fake")],
        make_path_labeler({"/real": True, "/fake": False}),
        "t",
    )
    p1 = write_dataset(rows, tmp_path / "a.jsonl")
    p2 = write_dataset(rows, tmp_path / "b.jsonl")
    assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
    back = read_dataset(p1)
    assert len(back) == 2
    assert {r["label_name"] for r in back} == {VALID_LABEL, FP_LABEL}


def test_dataset_summary_counts():
    rows = label_findings(
        [_finding("https://h/real"), _finding("https://h/fake")],
        make_path_labeler({"/real": True, "/fake": False}),
        "t",
    )
    summary = dataset_summary(rows)
    assert summary["total"] == 2
    assert summary["valid"] == 1
    assert summary["false_positive"] == 1


def _load_builder():
    import sys

    path = _REPO / "ml" / "build_dataset.py"
    spec = importlib.util.spec_from_file_location("_wily_build_dataset", path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: build_dataset uses `from __future__ import
    # annotations`, so its dataclass needs its module resolvable in sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_offline_secret_rows_are_balanced_and_labeled():
    """The embedded secret sources collection runs with no server/network and
    yields both VALID (real-shaped leaks) and FALSE_POSITIVE (placeholders)."""
    builder = _load_builder()
    rows = builder.collect_secret_rows()
    assert rows, "expected some secret-exposure rows"
    labels = {r["label_name"] for r in rows}
    assert VALID_LABEL in labels and FP_LABEL in labels
    # VALID secret rows should look like real leaks (high confidence); FP rows
    # like placeholders (lower confidence) - the signal the model learns.
    valid_conf = [r["confidence"] for r in rows if r["label_name"] == VALID_LABEL]
    fp_conf = [r["confidence"] for r in rows if r["label_name"] == FP_LABEL]
    assert min(valid_conf) > max(fp_conf)
