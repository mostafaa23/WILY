"""Train the optional triage classifier on a bootstrapped labeled dataset.

A deliberately small, inspectable model (scikit-learn ``LogisticRegression``
inside a ``StandardScaler`` pipeline) fit on the rows produced by
``risk/ml/dataset.py``. The point is not a state-of-the-art classifier - it is
to show, honestly and reproducibly, whether a model trained on the signals the
heuristic layer already computes can *re-rank* findings any better than the
heuristic score alone, while keeping recall (the honest guardrail) in view.

scikit-learn and joblib are optional (the ``[ml]`` extra). This module imports
them lazily and raises a clear, actionable error if they are missing, so the
rest of Wily never depends on them.

Honesty guardrails baked in:
  * The heuristic baseline is the existing ``heuristic_priority`` score turned
    into a classifier by picking its best-F1 threshold ON THE TRAINING split,
    then scored on the SAME held-out test split as the model - a fair "best the
    heuristic score alone can do" comparison.
  * Recall of the VALID class is reported for both and compared explicitly: if
    the model's recall is below the heuristic baseline's, ``recall_regressed``
    is True and the trainer shouts about it. A model that bought precision by
    silently dropping real vulnerabilities is a worse tool, not a better one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from wily.risk.ml.features import FEATURE_NAMES

_HEURISTIC_FEATURE = "heuristic_priority"
_MISSING_ML_DEPS_MSG = (
    "scikit-learn / joblib are required to train or load the triage model. "
    "Install the optional extra:  pip install 'wily[ml]'  (or: pip install "
    "scikit-learn joblib numpy)."
)


def _require_sklearn():
    try:
        import joblib  # noqa: F401
        import numpy  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_MISSING_ML_DEPS_MSG) from exc


@dataclass
class ClassMetrics:
    """Precision / recall / F1 for the VALID (positive) class, plus support."""

    precision: float
    recall: float
    f1: float
    n_test: int
    n_valid_test: int

    def as_line(self, label: str) -> str:
        return (
            f"{label:<22} precision={self.precision:.3f}  "
            f"recall={self.recall:.3f}  f1={self.f1:.3f}  "
            f"(test n={self.n_test}, valid={self.n_valid_test})"
        )


@dataclass
class TrainReport:
    n_samples: int
    n_valid: int
    n_false_positive: int
    feature_names: list[str]
    model: ClassMetrics
    heuristic_baseline: ClassMetrics
    heuristic_threshold: float
    cv_f1_mean: float
    cv_f1_std: float
    cv_recall_mean: float
    trained_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def recall_regressed(self) -> bool:
        """True when the model's VALID recall is below the heuristic baseline -
        the one outcome we refuse to let pass silently."""
        return self.model.recall < self.heuristic_baseline.recall - 1e-9

    def summary(self) -> dict:
        return asdict(self) | {"recall_regressed": self.recall_regressed}


def build_xy(rows: list[dict]) -> tuple[list[list[float]], list[int]]:
    """Feature matrix (FEATURE_NAMES order only) and integer labels. Provenance
    columns are ignored here, so nothing but real features reaches the model."""
    x = [[float(row.get(name, 0.0)) for name in FEATURE_NAMES] for row in rows]
    y = [int(row["label"]) for row in rows]
    return x, y


def _prf(y_true: list[int], y_pred: list[int]) -> ClassMetrics:
    from sklearn.metrics import f1_score, precision_score, recall_score

    return ClassMetrics(
        precision=float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        n_test=len(y_true),
        n_valid_test=int(sum(1 for v in y_true if v == 1)),
    )


def _best_threshold(scores: list[float], y_true: list[int]) -> float:
    """The decision threshold on a single score that maximises F1 for the VALID
    class on (training) data. Ties break toward the lower threshold (higher
    recall), consistent with recall being the guardrail."""
    from sklearn.metrics import f1_score

    candidates = sorted(set(scores))
    # Evaluate thresholds just below each distinct score (predict VALID when
    # score >= t) plus one above the max (predict all FP).
    best_t, best_f1 = (candidates[0] if candidates else 0.0), -1.0
    tried = [*candidates, (candidates[-1] + 1.0 if candidates else 1.0)]
    for t in tried:
        pred = [1 if s >= t else 0 for s in scores]
        f1 = f1_score(y_true, pred, pos_label=1, zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return float(best_t)


def train_classifier(
    rows: list[dict],
    *,
    test_size: float = 0.3,
    cv_folds: int = 5,
    seed: int = 1337,
) -> tuple[object, TrainReport]:
    """Fit the model on ``rows`` and return ``(model, report)``.

    ``model`` is a fitted scikit-learn pipeline. ``report`` carries the model's
    and the heuristic baseline's precision/recall/F1 on an identical held-out
    test split, cross-validated F1/recall on the training split, and the
    ``recall_regressed`` guardrail flag.
    """
    _require_sklearn()
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    x, y = build_xy(rows)
    if len(rows) < 4:
        raise ValueError(f"need at least 4 labeled rows to train, got {len(rows)}")
    n_valid = int(sum(y))
    n_fp = len(y) - n_valid
    if n_valid < 2 or n_fp < 2:
        raise ValueError(
            f"need at least 2 rows of each class to train and evaluate; "
            f"got valid={n_valid}, false_positive={n_fp}"
        )

    x_arr = np.asarray(x, dtype=float)
    y_arr = np.asarray(y, dtype=int)

    x_train, x_test, y_train, y_test = train_test_split(
        x_arr, y_arr, test_size=test_size, random_state=seed, stratify=y_arr
    )

    model = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "clf",
                # class_weight balanced protects the minority class so the model
                # is not tempted to maximise accuracy by calling everything FP.
                LogisticRegression(class_weight="balanced", max_iter=1000, random_state=seed),
            ),
        ]
    )
    model.fit(x_train, y_train)
    model_pred = model.predict(x_test).tolist()
    model_metrics = _prf(y_test.tolist(), model_pred)

    # Heuristic baseline: threshold the existing heuristic_priority score. Pick
    # the threshold on TRAIN, score on the SAME test split as the model.
    h_index = FEATURE_NAMES.index(_HEURISTIC_FEATURE)
    train_h = x_train[:, h_index].tolist()
    test_h = x_test[:, h_index].tolist()
    threshold = _best_threshold(train_h, y_train.tolist())
    baseline_pred = [1 if s >= threshold else 0 for s in test_h]
    baseline_metrics = _prf(y_test.tolist(), baseline_pred)

    # Cross-validation on the training split (honest generalisation estimate).
    folds = max(2, min(cv_folds, n_valid, n_fp, len(y_train)))
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    cv_f1 = cross_val_score(model, x_train, y_train, cv=skf, scoring="f1")
    cv_recall = cross_val_score(model, x_train, y_train, cv=skf, scoring="recall")

    report = TrainReport(
        n_samples=len(rows),
        n_valid=n_valid,
        n_false_positive=n_fp,
        feature_names=list(FEATURE_NAMES),
        model=model_metrics,
        heuristic_baseline=baseline_metrics,
        heuristic_threshold=threshold,
        cv_f1_mean=float(cv_f1.mean()),
        cv_f1_std=float(cv_f1.std()),
        cv_recall_mean=float(cv_recall.mean()),
    )
    return model, report


def save_bundle(model, report: TrainReport, path: str | Path) -> Path:
    """Persist the fitted model + the schema it was trained on + its metrics as
    one joblib artifact. Storing ``feature_names`` with the model lets the
    loader refuse a schema mismatch instead of mis-aligning columns."""
    _require_sklearn()
    import joblib

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "metrics": report.summary(),
        "trained_at": report.trained_at,
        "wily_model_kind": "logistic_regression_triage_v1",
    }
    joblib.dump(bundle, path)
    return path


def load_bundle(path: str | Path) -> dict:
    """Load a saved bundle. Raises if the ML extra is missing or the file's
    feature schema does not match this build's ``FEATURE_NAMES``."""
    _require_sklearn()
    import joblib

    bundle = joblib.load(path)
    saved = tuple(bundle.get("feature_names", ()))
    if saved != FEATURE_NAMES:
        raise ValueError(
            "model feature schema does not match this build of wily "
            f"(model has {len(saved)} features, this build expects "
            f"{len(FEATURE_NAMES)}); retrain with the current code."
        )
    return bundle
