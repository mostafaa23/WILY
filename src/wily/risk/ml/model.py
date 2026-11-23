"""Load and apply the optional trained triage model at scan time.

This is the thin, safe boundary between the (dependency-light) scan pipeline
and the (scikit-learn-backed) model. It is used only when a user explicitly
passes ``--ml-model <path>`` to ``wily scan``. When no model is enabled, none
of this runs and triage behaves EXACTLY as the heuristic-only default.

Guarantees, by design:
  * **Never crashes a scan.** ``load_triage_model`` returns ``None`` (with a
    recorded reason) if the ML extra is missing, the file is absent, or the
    model's feature schema does not match this build - the caller then simply
    falls back to heuristics.
  * **Never removes a finding.** The model only produces a per-finding
    probability that a finding is a real vulnerability. The ranker turns that
    into a small, bounded, sub-severity re-ranking boost and an evidence
    annotation; it cannot drop or hide a finding. Recall is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass

from wily.risk.ml.features import feature_vector


@dataclass
class TriageModel:
    """A loaded model that scores a single finding's probability of being a
    real (VALID) vulnerability, in [0, 1]."""

    model: object
    path: str
    trained_at: str = ""
    metrics: dict | None = None

    def valid_probability(self, finding) -> float:
        """P(finding is a real vulnerability), in [0, 1].

        Pure and defensive: a prediction failure on one odd finding returns a
        neutral 0.5 rather than aborting the scan."""
        try:
            vec = [feature_vector(finding)]
            proba = self.model.predict_proba(vec)[0]
            # Column index of the positive (VALID == 1) class.
            classes = list(getattr(self.model, "classes_", [0, 1]))
            idx = classes.index(1) if 1 in classes else len(classes) - 1
            return float(proba[idx])
        except Exception:
            return 0.5


def load_triage_model(path: str) -> tuple[TriageModel | None, str | None]:
    """Load a model bundle for use at scan time.

    Returns ``(model, None)`` on success or ``(None, reason)`` on any failure,
    so the caller can warn and fall back to heuristics without the scan dying.
    """
    try:
        from wily.risk.ml.training import load_bundle
    except Exception as exc:  # pragma: no cover - import guard
        return None, f"could not import model loader: {exc}"

    try:
        bundle = load_bundle(path)
    except FileNotFoundError:
        return None, f"model file not found: {path}"
    except Exception as exc:
        return None, str(exc)

    return (
        TriageModel(
            model=bundle["model"],
            path=str(path),
            trained_at=bundle.get("trained_at", ""),
            metrics=bundle.get("metrics"),
        ),
        None,
    )
