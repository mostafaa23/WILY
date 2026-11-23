"""Tests for wiring the optional trained model into triage (ranker + loader).

The no-op guarantee (no model -> behaviour byte-for-byte unchanged) needs no
scikit-learn. The model-on behaviour is skipped without the [ml] extra.
"""

from __future__ import annotations

import pytest

from wily.risk.ml.model import load_triage_model
from wily.risk.ml.ranker import rank_findings
from wily.scanners.base import Finding


def _mk(category, severity, confidence, evidence=None):
    return Finding(
        asset="https://h/orders/1",
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=evidence or {},
        discovery_source="scanner",
    )


def _sample():
    return [
        _mk("authz-bypass-missing-authorizer", "critical", 0.9,
            {"body_similarity_to_soft_404_baseline": 1.0}),
        _mk("authz-bypass-missing-authorizer", "critical", 0.9,
            {"body_similarity_to_soft_404_baseline": 0.05}),
        _mk("secret-exposure-generic-api-key", "medium", 0.45, {}),
    ]


def test_ranking_without_model_adds_no_ml_keys():
    ranked = rank_findings(_sample(), model=None)
    assert len(ranked) == 3
    for f in ranked:
        assert "ml_valid_probability" not in f.evidence
        assert "rank_score" in f.evidence  # heuristic annotations still happen


def test_ranking_without_model_matches_default_arg():
    """Passing model=None must equal the historical single-arg call exactly."""
    a = rank_findings(_sample())
    b = rank_findings(_sample(), model=None)
    assert [f.evidence["rank_score"] for f in a] == [f.evidence["rank_score"] for f in b]
    assert [f.category for f in a] == [f.category for f in b]


def test_load_missing_model_is_graceful():
    model, reason = load_triage_model("does/not/exist.joblib")
    assert model is None
    assert reason  # a human-readable reason, not a crash


# --- model-on behaviour (needs scikit-learn) --------------------------------
def _tiny_model(tmp_path):
    pytest.importorskip("sklearn")
    from wily.risk.ml.dataset import finding_to_row
    from wily.risk.ml.training import save_bundle, train_classifier

    rows = []
    for _i in range(8):
        rows.append(finding_to_row(
            _mk("authz-bypass-missing-authorizer", "critical", 0.95,
                {"body_similarity_to_soft_404_baseline": 0.05}),
            "VALID", "fix"))
        rows.append(finding_to_row(
            _mk("authz-bypass-missing-authorizer", "critical", 0.9,
                {"body_similarity_to_soft_404_baseline": 1.0}),
            "FALSE_POSITIVE", "fix"))
    model, report = train_classifier(rows, seed=0)
    path = save_bundle(model, report, tmp_path / "m.joblib")
    loaded, reason = load_triage_model(str(path))
    assert loaded is not None, reason
    return loaded


def test_model_annotates_and_reranks_without_dropping(tmp_path):
    pytest.importorskip("sklearn")
    model = _tiny_model(tmp_path)
    findings = _sample()
    ranked = rank_findings(findings, model=model)

    # Never drops a finding.
    assert len(ranked) == len(findings)
    # Annotates every finding with a model probability + a rank reason.
    for f in ranked:
        assert "ml_valid_probability" in f.evidence
        assert any("ml model" in r for r in f.evidence["rank_reasons"])
    # The real authz finding (low soft-404 similarity) must out-rank the
    # catch-all FP (similarity 1.0) once the model re-ranks.
    authz = [f for f in ranked if f.category == "authz-bypass-missing-authorizer"]
    real, fp = None, None
    for f in authz:
        if f.evidence["body_similarity_to_soft_404_baseline"] < 0.5:
            real = f
        else:
            fp = f
    assert ranked.index(real) < ranked.index(fp)


def test_model_boost_is_bounded_sub_severity(tmp_path):
    """The model can only nudge priority by at most +/-0.5 - it never lets a
    low-severity finding leapfrog a critical one on the model's say-so."""
    pytest.importorskip("sklearn")
    model = _tiny_model(tmp_path)
    f = _mk("authz-bypass-missing-authorizer", "critical", 0.9,
            {"body_similarity_to_soft_404_baseline": 0.05})
    base_only = rank_findings([f], model=None)[0].evidence["rank_score"]
    with_model = rank_findings([_mk("authz-bypass-missing-authorizer", "critical", 0.9,
                               {"body_similarity_to_soft_404_baseline": 0.05})],
                               model=model)[0].evidence["rank_score"]
    assert abs(with_model - base_only) <= 0.5 + 1e-9
