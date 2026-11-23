"""Bootstrap a LABELED triage dataset from known-ground-truth targets.

The chicken-and-egg problem a trained triage model faces is that it needs
labeled findings, which would normally only come from many analysts marking
real scans VALID / FALSE_POSITIVE over a long time. For a project with no such
field data yet, this module bootstraps the labels instead, from targets whose
ground truth we already know: the benchmark app and the ``demo/vulnerable_*``
apps, each of which declares (or is extended to declare) a ``GROUND_TRUTH``.

This module holds only the *pure, dependency-light* pieces - labeling,
feature-row assembly, and dataset read/write. The offline orchestration that
actually stands up the local Flask targets and runs the scanners lives in the
runnable ``ml/build_dataset.py`` script, so the package itself never imports
Flask or binds a socket.

A row is a flat dict: every ``features.FEATURE_NAMES`` column, plus the label
and a little provenance (``label_name``, ``category``, ``asset``, ``source``)
for auditing. The provenance columns are NOT features and the trainer ignores
them; only ``FEATURE_NAMES`` feed the model, so there is no label leakage.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path
from urllib.parse import urlparse

from wily.risk.ml.dedup import finding_hash_key, get_field
from wily.risk.ml.features import FEATURE_NAMES, extract_features

VALID_LABEL = "VALID"
FP_LABEL = "FALSE_POSITIVE"
# Numeric encoding used by the trainer: 1 == a real vulnerability worth an
# analyst's time, 0 == a false positive. Recall (of the VALID class) is the
# honest guardrail, so VALID is the positive class on purpose.
_LABEL_TO_INT = {VALID_LABEL: 1, FP_LABEL: 0}

# Provenance columns written alongside the features. Kept OUT of FEATURE_NAMES
# so they are never fed to the model.
_PROVENANCE_COLUMNS = ("label", "label_name", "category", "asset", "source")


def path_of(asset: str) -> str:
    """The URL path of a finding's asset, matched against path-keyed ground
    truth. A non-URL asset (a bare label, an ``s3://`` ref) is returned as-is."""
    asset = asset or ""
    parsed = urlparse(asset)
    if not parsed.scheme:
        return asset
    return parsed.path or "/"


def make_path_labeler(ground_truth: dict[str, bool]) -> Callable[[object], str | None]:
    """Build a labeler from a path -> is-real-vulnerability map (the shape the
    benchmark and demo apps declare).

    Returns VALID for a finding on a path ground truth marks ``True``,
    FALSE_POSITIVE for a path marked ``False``, and ``None`` (skip - we have no
    ground truth for it) for a path not in the map. This mirrors
    ``benchmark/run_benchmark.score_run`` exactly, so the dataset's notion of a
    true/false positive is the same one the benchmark reports.
    """

    def labeler(finding) -> str | None:
        path = path_of(get_field(finding, "asset", "") or "")
        verdict = ground_truth.get(path)
        if verdict is True:
            return VALID_LABEL
        if verdict is False:
            return FP_LABEL
        return None

    return labeler


def finding_to_row(finding, label_name: str, source: str) -> dict:
    """One labeled dataset row: all feature columns + label + provenance."""
    row: dict = dict(extract_features(finding))
    row["label"] = _LABEL_TO_INT[label_name]
    row["label_name"] = label_name
    row["category"] = get_field(finding, "category", "") or ""
    row["asset"] = get_field(finding, "asset", "") or ""
    row["source"] = source
    return row


def label_findings(
    findings: Iterable,
    labeler: Callable[[object], str | None],
    source: str,
    *,
    feedback: dict[str, str] | None = None,
) -> list[dict]:
    """Turn scanned findings into labeled rows.

    Each finding is labeled by ``labeler`` (ground truth). If a ``feedback``
    map (``finding_hash_key`` -> ``VALID``/``FALSE_POSITIVE``) is supplied and
    it has a decision for this finding, that analyst verdict OVERRIDES the
    ground-truth label (a real human looked at it), and the row's source is
    tagged ``"<source>+feedback"``. Findings with neither a ground-truth nor a
    feedback label are skipped - we never invent a label.
    """
    feedback = feedback or {}
    rows: list[dict] = []
    for finding in findings:
        label_name = labeler(finding)
        row_source = source
        try:
            key = finding_hash_key(finding)
        except Exception:
            key = None
        if key is not None and key in feedback:
            label_name = feedback[key]
            row_source = f"{source}+feedback"
        if label_name not in _LABEL_TO_INT:
            continue
        rows.append(finding_to_row(finding, label_name, row_source))
    return rows


def write_dataset(rows: list[dict], path: str | Path) -> Path:
    """Write rows as JSONL (one compact JSON object per line). Deterministic:
    keys are emitted in a fixed order (features in schema order, then
    provenance) so two builds of the same findings produce byte-identical
    files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered_keys = [*FEATURE_NAMES, *_PROVENANCE_COLUMNS]
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            ordered = {k: row[k] for k in ordered_keys if k in row}
            fh.write(json.dumps(ordered, ensure_ascii=False, sort_keys=False) + "\n")
    return path


def read_dataset(path: str | Path) -> list[dict]:
    """Read a JSONL dataset back. A malformed line is skipped, not fatal."""
    path = Path(path)
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict) and "label" in data:
            rows.append(data)
    return rows


def dataset_summary(rows: list[dict]) -> dict:
    """Counts an analyst can sanity-check: totals, per-label, per-source,
    per-category-family."""
    labels = Counter(r.get("label_name", "?") for r in rows)
    sources = Counter(r.get("source", "?") for r in rows)
    categories = Counter(r.get("category", "?") for r in rows)
    return {
        "total": len(rows),
        "valid": labels.get(VALID_LABEL, 0),
        "false_positive": labels.get(FP_LABEL, 0),
        "by_source": dict(sorted(sources.items())),
        "by_category": dict(sorted(categories.items())),
    }
