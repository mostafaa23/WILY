"""Tests for the deterministic ML feature extractor (risk/ml/features.py)."""

from __future__ import annotations

from wily.risk.ml.features import (
    FEATURE_NAMES,
    extract_features,
    feature_vector,
)
from wily.scanners.base import Finding


def _finding(**overrides) -> Finding:
    base = {
        "asset": "https://api.example.com/orders/1",
        "category": "authz-bypass-missing-authorizer",
        "severity": "critical",
        "confidence": 0.9,
        "evidence": {},
        "discovery_source": "scanner",
    }
    base.update(overrides)
    return Finding(**base)


def test_vector_length_matches_schema():
    vec = feature_vector(_finding())
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vec)


def test_extract_keys_are_exactly_the_schema():
    feats = extract_features(_finding())
    assert set(feats) == set(FEATURE_NAMES)


def test_extraction_is_pure_does_not_mutate_finding():
    f = _finding(evidence={"body_similarity_to_soft_404_baseline": 0.99})
    before = dict(f.evidence)
    extract_features(f)
    feature_vector(f)
    assert f.evidence == before  # no rank_score / side effects written


def test_severity_and_confidence_scaled():
    feats = extract_features(_finding(severity="critical", confidence=1.0))
    assert feats["severity_rank"] == 1.0
    assert feats["confidence"] == 1.0
    assert feats["risk_score"] == 1.0

    low = extract_features(_finding(severity="info", confidence=0.0))
    assert low["severity_rank"] < 1.0
    assert low["confidence"] == 0.0


def test_confidence_is_clamped():
    feats = extract_features(_finding(confidence=5.0))
    assert feats["confidence"] == 1.0


def test_missing_similarity_is_not_zero_but_flagged_absent():
    absent = extract_features(_finding(evidence={}))
    assert absent["soft_404_similarity"] == 0.0
    assert absent["has_soft_404_similarity"] == 0.0

    present_zero = extract_features(
        _finding(evidence={"body_similarity_to_soft_404_baseline": 0.0})
    )
    assert present_zero["soft_404_similarity"] == 0.0
    assert present_zero["has_soft_404_similarity"] == 1.0  # distinguishes the two

    present_high = extract_features(
        _finding(evidence={"body_similarity_to_soft_404_baseline": 0.97})
    )
    assert present_high["soft_404_similarity"] == 0.97
    assert present_high["has_soft_404_similarity"] == 1.0


def test_bola_grounding_encoded():
    observed = extract_features(
        _finding(category="bola-idor", evidence={"grounding": "observed"})
    )
    seeded = extract_features(
        _finding(category="bola-idor", evidence={"grounding": "seeded"})
    )
    unowned = extract_features(
        _finding(category="bola-idor", evidence={"grounding": "unowned"})
    )
    absent = extract_features(_finding(category="bola-idor", evidence={}))
    assert observed["bola_grounding"] > seeded["bola_grounding"] > unowned["bola_grounding"]
    assert absent["bola_grounding"] == 0.0  # distinct from the weakest grounding


def test_live_credential_flag():
    live = extract_features(
        _finding(
            category="secret-exposure-aws-access-key",
            evidence={"is_live_cloud_credential": True},
        )
    )
    not_live = extract_features(
        _finding(
            category="secret-exposure-generic-token",
            evidence={"is_live_cloud_credential": False},
        )
    )
    assert live["is_live_cloud_credential"] == 1.0
    assert not_live["is_live_cloud_credential"] == 0.0


def test_category_one_hot_exactly_one_set():
    for category, expected in [
        ("authz-bypass-missing-authorizer", "category__authz-bypass"),
        ("bola-idor", "category__bola"),
        ("secret-exposure-aws-access-key", "category__secret-exposure"),
        ("cloud-ssrf-imds-v1", "category__cloud-ssrf"),
        ("something-brand-new", "category__other"),
    ]:
        feats = extract_features(_finding(category=category))
        hot = [k for k in FEATURE_NAMES if k.startswith("category__") and feats[k] == 1.0]
        assert hot == [expected], (category, hot)


def test_no_label_leakage_feedback_verdict_ignored():
    """The analyst verdict IS the label; it must never become a feature."""
    valid = _finding(evidence={"feedback_verdict": "valid"})
    fp = _finding(evidence={"feedback_verdict": "false_positive"})
    assert extract_features(valid) == extract_features(fp)
    assert not any("feedback" in name for name in FEATURE_NAMES)


def test_works_on_plain_dict_like_a_reloaded_report():
    as_dict = {
        "asset": "https://api.example.com/orders/1",
        "category": "authz-bypass-missing-authorizer",
        "severity": "high",
        "confidence": 0.8,
        "evidence": {"body_similarity_to_soft_404_baseline": 0.1},
    }
    feats = extract_features(as_dict)
    assert set(feats) == set(FEATURE_NAMES)
    assert feats["has_soft_404_similarity"] == 1.0


def test_cluster_counts_scaled_and_capped():
    feats = extract_features(
        _finding(evidence={"duplicate_count": 999, "merged_endpoint_count": 999})
    )
    assert feats["duplicate_count"] == 1.0  # capped
    assert feats["merged_endpoint_count"] == 1.0
