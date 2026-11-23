"""Train the optional triage classifier on the bootstrapped dataset.

Reads the JSONL dataset produced by ml/build_dataset.py, fits a small
LogisticRegression pipeline (wily.risk.ml.training), and reports precision,
recall and F1 on a held-out test split for BOTH the model and the pure
heuristic-priority baseline, scored identically. Recall of the VALID class is
printed prominently because it is the honest guardrail: a model that trades
recall for precision (i.e. buys a cleaner report by hiding real
vulnerabilities) is called out, not celebrated.

    python ml/train.py
    python ml/train.py --data ml/data/triage_dataset.jsonl --out ml/models/triage_model.joblib

The saved artifact is small (a joblib pickle of the fitted pipeline + the
feature schema it was trained on + its metrics), so the loader can refuse a
schema mismatch instead of silently mis-aligning columns.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parent
_REPO = _ML_DIR.parent
sys.path.insert(0, str(_REPO / "src"))

from wily.risk.ml.dataset import read_dataset  # noqa: E402
from wily.risk.ml.training import save_bundle, train_classifier  # noqa: E402

_DEFAULT_DATA = _ML_DIR / "data" / "triage_dataset.jsonl"
_DEFAULT_OUT = _ML_DIR / "models" / "triage_model.joblib"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=str(_DEFAULT_DATA), help="input JSONL dataset")
    parser.add_argument("--out", default=str(_DEFAULT_OUT), help="output model (joblib)")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    rows = read_dataset(args.data)
    if not rows:
        print(f"[!] no rows in {args.data}; run: python ml/build_dataset.py", file=sys.stderr)
        return 2

    try:
        model, report = train_classifier(
            rows, test_size=args.test_size, cv_folds=args.cv_folds, seed=args.seed
        )
    except ValueError as exc:
        print(f"[!] cannot train: {exc}", file=sys.stderr)
        return 2

    path = save_bundle(model, report, args.out)

    print("=" * 68)
    print("Wily triage model - bootstrapped from known-ground-truth targets")
    print("=" * 68)
    print(
        f"dataset: {report.n_samples} rows "
        f"({report.n_valid} VALID / {report.n_false_positive} FALSE_POSITIVE), "
        f"{len(report.feature_names)} features"
    )
    print(f"cross-val (train): F1 {report.cv_f1_mean:.3f} +/- {report.cv_f1_std:.3f}, "
          f"recall {report.cv_recall_mean:.3f}")
    print("-" * 68)
    print(report.heuristic_baseline.as_line("heuristic baseline"))
    print(report.model.as_line("trained model"))
    print("-" * 68)
    d_recall = report.model.recall - report.heuristic_baseline.recall
    d_prec = report.model.precision - report.heuristic_baseline.precision
    print(f"model vs baseline: recall {d_recall:+.3f}, precision {d_prec:+.3f}")
    if report.recall_regressed:
        print(
            "\n[!!] RECALL REGRESSED: the model's VALID recall is BELOW the heuristic "
            "baseline. It is hiding real vulnerabilities to look cleaner - do NOT ship "
            "this model as-is. Recall is the guardrail."
        )
    else:
        print("\n[ok] recall is at or above the heuristic baseline (guardrail held).")

    metrics_path = Path(args.out).with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(report.summary(), indent=2), encoding="utf-8")
    print(f"\nmodel written to   {path.resolve()}")
    print(f"metrics written to {metrics_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
