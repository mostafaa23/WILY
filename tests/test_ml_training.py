"""Tests for the triage trainer (risk/ml/training.py).

Skipped wholesale when scikit-learn is not installed, so the suite stays green
without the optional [ml] extra. With it, a tiny separable fixture must train a
model, report sane metrics, hold the recall guardrail, and round-trip through
joblib with a feature-schema check.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sklearn")

from wily.risk.ml.dataset import finding_to_row
from wily.risk.ml.training import (
    build_xy,
    load_bundle,
    save_bundle,
    train_classifier,
)
from wily.scanners.base import Finding


def _valid_finding(i: int) -> Finding:
    # A real authz leak: high confidence, body unlike the soft-404 baseline.
    return Finding(
        asset=f"https://h/orders/{i}",
        category="authz-bypass-missing-authorizer",
        severity="critical",
        confidence=0.95,
        evidence={"body_similarity_to_soft_404_baseline": 0.05},
        discovery_source="scanner",
    )


def _fp_finding(i: int) -> Finding:
    # A catch-all false positive: same severity, but body == the soft-404
    # baseline (similarity 1.0) - the signal the heuristic priority can't see.
    return Finding(
        asset=f"https://h/catchall/{i}",
        category="authz-bypass-missing-authorizer",
        severity="critical",
        confidence=0.9,
        evidence={"body_similarity_to_soft_404_baseline": 1.0},
        discovery_source="scanner",
    )


def _fixture_rows(n: int = 8) -> list[dict]:
    rows = [finding_to_row(_valid_finding(i), "VALID", "fix") for i in range(n)]
    rows += [finding_to_row(_fp_finding(i), "FALSE_POSITIVE", "fix") for i in range(n)]
    return rows


def test_build_xy_shapes():
    rows = _fixture_rows(4)
    x, y = build_xy(rows)
    assert len(x) == len(y) == 8
    assert sum(y) == 4  # four VALID


def test_train_produces_model_and_sane_metrics():
    model, report = train_classifier(_fixture_rows(8), seed=0)
    assert report.n_samples == 16
    assert report.n_valid == 8 and report.n_false_positive == 8
    # On a cleanly separable fixture the model should score well and keep recall.
    assert 0.0 <= report.model.precision <= 1.0
    assert report.model.recall >= 0.5
    assert report.model.f1 > 0.0
    assert not report.recall_regressed  # guardrail held
    # predict_proba works through the fitted pipeline.
    proba = model.predict_proba([[0.0] * len(report.feature_names)])
    assert proba.shape[1] == 2


def test_too_few_rows_raises():
    with pytest.raises(ValueError):
        train_classifier(_fixture_rows(1))  # 2 rows total, not enough


def test_save_and_load_roundtrip(tmp_path):
    model, report = train_classifier(_fixture_rows(8), seed=0)
    path = save_bundle(model, report, tmp_path / "m.joblib")
    bundle = load_bundle(path)
    assert bundle["model"] is not None
    assert tuple(bundle["feature_names"])  # schema stored
    assert bundle["metrics"]["n_samples"] == 16


def test_load_rejects_schema_mismatch(tmp_path, monkeypatch):
    import joblib

    joblib.dump(
        {"model": object(), "feature_names": ["only", "two"]},
        tmp_path / "bad.joblib",
    )
    with pytest.raises(ValueError, match="feature schema"):
        load_bundle(tmp_path / "bad.joblib")
