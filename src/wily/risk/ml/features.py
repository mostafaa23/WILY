"""Deterministic feature extraction for the (optional) trained triage model.

Turns a single ``Finding`` into a FIXED, DOCUMENTED, numeric feature vector,
reusing signals that already exist elsewhere in the pipeline (severity,
confidence, the heuristic risk/priority scores, the response-sensitivity
adjustment, BOLA ownership grounding, the live-credential flag, the
differential soft-404 / authenticated-baseline similarities, and the
dedup/endpoint-cluster counts) plus a small one-hot of the finding's category
family.

Design rules, so the dataset this produces is honest:

  * **No label leakage.** The training label (VALID / FALSE_POSITIVE) is the
    analyst/ground-truth verdict. This extractor therefore NEVER reads
    ``evidence['feedback_verdict']`` (that *is* the label) nor any field that
    is only populated once a label is known. It only reads signals a scanner
    produced before any human looked at the finding.
  * **Fixed, ordered, documented.** ``FEATURE_NAMES`` is the schema; every
    vector has exactly ``len(FEATURE_NAMES)`` floats in that order. Adding a
    feature means appending to ``FEATURE_NAMES`` and a model artifact records
    the schema it was trained on, so a mismatch is caught, not silently
    mis-aligned.
  * **Missing != zero.** A similarity that was never computed is distinct from
    a computed similarity of 0.0, so each optional-similarity signal carries a
    companion ``has_*`` presence flag rather than defaulting to 0.0.
  * **Pure.** Extracting features never mutates the finding, so it is safe to
    call from a sort key, a test, or the live pipeline.

Works on a ``Finding`` dataclass (the live pipeline) or a plain ``dict``
reloaded from a JSON report (the dataset builder / ``wily triage``), via the
same attribute-or-key access helper the dedup/feedback modules already use.
"""

from __future__ import annotations

from wily.risk.ml.dedup import get_field
from wily.risk.ml.sensitivity import score_response
from wily.risk.scoring import _SEVERITY_WEIGHTS, compute_risk_score

# Category-family prefixes, matched by ``str.startswith`` in order (first match
# wins). A finding whose category matches none of these falls into the trailing
# "other" bucket. Kept deliberately small and explicit so the one-hot is stable
# across releases; a new family is an append, never a reshuffle.
_CATEGORY_FAMILIES: tuple[str, ...] = (
    "authz-bypass",
    "bola",
    "secret-exposure",
    "cloud-ssrf",
    "iam-privesc",
    "s3-bucket",
    "takeover",
    "jwt",
    "session",
    "cors",
)

# BOLA ownership grounding -> how strongly a cross-tenant leak was attributed.
# Mirrors ranker._BOLA_GROUNDING_BOOST's ordering; absent grounding is 0.0
# (no attribution signal at all), kept distinct from the weakest "unowned".
_BOLA_GROUNDING_ENCODING = {"observed": 1.0, "seeded": 0.6, "unowned": 0.3}

# Evidence keys that may carry response text worth running the heuristic
# sensitivity scorer on. Same list ranker._sensitivity_boost uses, kept in sync
# on purpose so the model sees the same signal the heuristic does.
_SENSITIVITY_TEXT_KEYS = ("context", "snippet", "body_snippet", "masked_secret")

# Normalisation constants. The model is scale-tolerant (we standardise in the
# trainer), but keeping raw-ish features in a roughly 0..1 range makes the
# dataset readable and the untrained-model path well-behaved.
_MAX_SEVERITY_WEIGHT = float(max(_SEVERITY_WEIGHTS.values()))  # critical == 10
_MAX_RISK_SCORE = 10.0            # compute_risk_score tops out at severity*1.0
_MAX_PRIORITY = 13.0              # base risk (<=10) + impact/corr/sensitivity boosts
_CLUSTER_CAP = 20.0              # cap + scale the two cluster-size counts


def _base_feature_names() -> tuple[str, ...]:
    return (
        "severity_rank",                 # severity weight / 10, in [0,1]
        "confidence",                    # finding confidence, in [0,1]
        "risk_score",                    # compute_risk_score / 10, in [0,1]
        "heuristic_priority",            # ranker.priority_score / 13, ~[0,1]
        "sensitivity_adjustment",        # sensitivity.score_response signed value
        "bola_grounding",                # encoded ownership grounding, in [0,1]
        "is_live_cloud_credential",      # 1.0 if secret scan confirmed live cred
        "soft_404_similarity",           # differential baseline similarity or 0.0
        "has_soft_404_similarity",       # 1.0 if the above was actually computed
        "authenticated_similarity",      # unauth-vs-authenticated body sim or 0.0
        "has_authenticated_similarity",  # 1.0 if the above was actually computed
        "duplicate_count",               # near-dup cluster size, capped+scaled
        "merged_endpoint_count",         # endpoint-hash cluster size, capped+scaled
    )


# The full, fixed feature schema: the base signals above, then one column per
# category family, then the "other" bucket. This tuple IS the contract.
FEATURE_NAMES: tuple[str, ...] = (
    *_base_feature_names(),
    *(f"category__{family}" for family in _CATEGORY_FAMILIES),
    "category__other",
)


def _as_float(value, default: float = 0.0) -> float:
    try:
        if value is None or isinstance(value, bool):
            return float(default) if value is None else float(bool(value))
        return float(value)
    except (TypeError, ValueError):
        return default


def _heuristic_priority(finding) -> float:
    """ranker.priority_score, imported lazily to avoid any import-order
    surprise (ranker imports sensitivity/scoring; it does not import this
    module, so there is no cycle - the lazy import is pure caution)."""
    from wily.risk.ml.ranker import priority_score

    return priority_score(finding)


def _sensitivity_adjustment(evidence: dict) -> float:
    for key in _SENSITIVITY_TEXT_KEYS:
        value = evidence.get(key)
        if isinstance(value, str) and value:
            adjustment, reason = score_response(value)
            return adjustment if reason is not None else 0.0
    return 0.0


def _category_one_hot(category: str) -> list[float]:
    """One-hot over ``_CATEGORY_FAMILIES`` (first startswith match wins) with a
    trailing ``other`` column. Exactly one column is 1.0."""
    hot = [0.0] * (len(_CATEGORY_FAMILIES) + 1)
    for i, family in enumerate(_CATEGORY_FAMILIES):
        if category.startswith(family):
            hot[i] = 1.0
            return hot
    hot[-1] = 1.0  # "other"
    return hot


def extract_features(finding) -> dict[str, float]:
    """Return the fixed numeric feature map for one finding.

    The keys are exactly ``FEATURE_NAMES``. Pure: never mutates ``finding``.
    Accepts a ``Finding`` dataclass or a dict reloaded from a report.
    """
    severity = get_field(finding, "severity", "info") or "info"
    confidence = _as_float(get_field(finding, "confidence", 0.0))
    confidence = max(0.0, min(confidence, 1.0))
    category = get_field(finding, "category", "") or ""

    evidence = get_field(finding, "evidence", None)
    if not isinstance(evidence, dict):
        evidence = {}

    severity_weight = float(_SEVERITY_WEIGHTS.get(severity, 1))
    risk = compute_risk_score(severity, confidence)

    # Optional similarity signals: value + presence flag (missing != 0.0).
    soft_404 = evidence.get("body_similarity_to_soft_404_baseline")
    auth_sim = evidence.get("body_similarity_to_authenticated")
    soft_404_present = isinstance(soft_404, (int, float)) and not isinstance(soft_404, bool)
    auth_sim_present = isinstance(auth_sim, (int, float)) and not isinstance(auth_sim, bool)

    grounding = evidence.get("grounding")
    bola_grounding = _BOLA_GROUNDING_ENCODING.get(grounding, 0.0)

    dup = _as_float(evidence.get("duplicate_count", 1), 1.0)
    merged = _as_float(evidence.get("merged_endpoint_count", 0), 0.0)

    base = {
        "severity_rank": severity_weight / _MAX_SEVERITY_WEIGHT,
        "confidence": confidence,
        "risk_score": risk / _MAX_RISK_SCORE,
        "heuristic_priority": min(_heuristic_priority(finding) / _MAX_PRIORITY, 1.0),
        "sensitivity_adjustment": _sensitivity_adjustment(evidence),
        "bola_grounding": bola_grounding,
        "is_live_cloud_credential": 1.0 if evidence.get("is_live_cloud_credential") else 0.0,
        "soft_404_similarity": _as_float(soft_404) if soft_404_present else 0.0,
        "has_soft_404_similarity": 1.0 if soft_404_present else 0.0,
        "authenticated_similarity": _as_float(auth_sim) if auth_sim_present else 0.0,
        "has_authenticated_similarity": 1.0 if auth_sim_present else 0.0,
        "duplicate_count": min(dup, _CLUSTER_CAP) / _CLUSTER_CAP,
        "merged_endpoint_count": min(merged, _CLUSTER_CAP) / _CLUSTER_CAP,
    }

    one_hot = _category_one_hot(category)
    for family, value in zip(_CATEGORY_FAMILIES, one_hot, strict=False):
        base[f"category__{family}"] = value
    base["category__other"] = one_hot[-1]

    return base


def feature_vector(finding) -> list[float]:
    """The finding's features as a plain list in ``FEATURE_NAMES`` order."""
    feats = extract_features(finding)
    return [feats[name] for name in FEATURE_NAMES]
