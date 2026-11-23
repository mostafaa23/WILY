# ML triage: a trainable layer on top of the heuristics

Wily's triage/ranking layer is **heuristic by default** (`src/wily/risk/ml/`:
`ranker.py`, `sensitivity.py`, `dedup.py`, `feedback.py`). This document
describes the **optional** trained layer that sits on top of it: a small
classifier that re-ranks findings using the signals the heuristics already
compute. It is off unless you explicitly enable it, and when off, ranking is
byte-for-byte identical to the heuristic-only behaviour.

> **Honest framing, up front.** This model is **bootstrapped from constructed
> targets whose ground truth we already declare** (the benchmark app, the demo
> apps, and a set of embedded secret look-alikes). It is **not** a
> field-trained model learned from real analyst decisions across many real
> scans. It exists to show the pipeline end-to-end — feature extraction →
> labeled dataset → trained model → optional re-ranking — and to demonstrate,
> on a known target, that a model over these features can separate the
> catch-all false positives from real bugs that the heuristic *priority score*
> alone cannot. Treat the metrics as a proof-of-pipeline, not a field result.

## The chicken-and-egg problem it solves

A trained triage model needs labeled findings (VALID vs FALSE_POSITIVE). In the
field those only accumulate slowly, one analyst decision at a time
(`feedback.py`'s `FeedbackStore`). To get a labeled dataset *now*, we generate
the labels from targets whose ground truth is already known and declared in the
repo, so no external users and no network are required.

## The four pieces

| Piece | Where | What it does |
| --- | --- | --- |
| Feature extractor | `src/wily/risk/ml/features.py` | One `Finding` → a fixed, documented numeric vector (`FEATURE_NAMES`). No label leakage. |
| Dataset layer | `src/wily/risk/ml/dataset.py` | Labeling, feature-row assembly, JSONL read/write. Dependency-light (no scikit-learn). |
| Dataset builder | `ml/build_dataset.py` | Runs scanners against known-ground-truth targets offline and writes the labeled dataset. |
| Trainer | `src/wily/risk/ml/training.py` + `ml/train.py` | Fits a `LogisticRegression` pipeline, reports precision/recall/F1 vs the heuristic baseline, saves a joblib artifact. |
| Scan-time loader | `src/wily/risk/ml/model.py` | Loads a model for `wily scan --ml-model` and re-ranks without ever dropping a finding. |

### Features (`features.py`)

`FEATURE_NAMES` is the schema; every vector has exactly that many floats in that
order. Features reuse signals that already exist on a finding **before** any
human looks at it: severity rank, confidence, `risk_score`, the heuristic
priority, the `sensitivity.py` adjustment, BOLA ownership `grounding`, the
secret `is_live_cloud_credential` flag, the differential soft-404 and
authenticated-baseline similarities (each with a "was it computed" presence
flag, so *missing* is distinct from *0.0*), the dedup/endpoint-cluster counts,
and a one-hot of the category family.

**No label leakage:** the extractor never reads `evidence['feedback_verdict']`
(that *is* the label) nor anything only populated after a label is known. A unit
test asserts two findings that differ only in a planted `feedback_verdict`
produce identical feature vectors.

## Reproduce it (offline, ~30 s)

Install the optional extra once:

```powershell
pip install "scikit-learn>=1.4" joblib numpy
```

(or `pip install -e ".[ml]"` — the `[ml]` extra in `pyproject.toml` pins
`scikit-learn` + `numpy`; `joblib` ships with scikit-learn.)

Build the dataset, then train:

```powershell
python ml/build_dataset.py
```

```powershell
python ml/train.py
```

`build_dataset.py` writes `ml/data/triage_dataset.jsonl`; `train.py` writes
`ml/models/triage_model.joblib` (+ a `.metrics.json`). Both are deterministic
(fixed seed, fixed row ordering), so a re-run reproduces the same artifact.

### What the builder scans

1. **Embedded secret sources** (no server, always available): real-shaped
   leaked credentials (AWS key, GitHub token, PEM private key) labeled VALID vs.
   documentation/placeholder look-alikes (example bearer token, `REPLACE_ME`
   API keys) labeled FALSE_POSITIVE — a well-known secret-scanner FP class.
2. **The benchmark app** (`benchmark/vulnerable_benchmark_api.py`, committed):
   its declared `GROUND_TRUTH` labels the real missing-authorizer bug VALID and
   the generic catch-all 200s FALSE_POSITIVE.
3. **The demo authz app** (`demo/vulnerable_authz_api.py`) when present — it now
   declares a `GROUND_TRUTH` too. `demo/` is local-only (gitignored), so this is
   optional augmentation that simply adds rows when you have the dev tree.
4. **Optional analyst feedback**: `python ml/build_dataset.py --feedback
   path/to/feedback.jsonl` folds in a `FeedbackStore` log; a matching analyst
   verdict **overrides** the ground-truth label.

The authz scanner runs with the soft-404 probe enabled but its filter threshold
set above 1.0, so the catch-all false positives are **kept and labeled** (not
silently filtered) — they are exactly what we want the model to learn from.

### Adding external targets (not required)

Real vulnerable apps — OWASP Juice Shop, VAmPI, crAPI — fold in the same way:
stand one up locally yourself, then add an `HttpAuthzTarget(name=..., app or
base_url=..., ground_truth={path: is_real_bug})` to `build_dataset.py` for the
endpoints whose ground truth you know. Nothing in Wily reaches those apps on its
own; you run them.

## The metrics (and how to read them honestly)

On the committed bootstrapped dataset (**18 rows, 9 VALID / 9 FALSE_POSITIVE,
24 features**, seed 1337, 30 % held-out test):

```
heuristic baseline     precision=0.500  recall=1.000  f1=0.667  (test n=6, valid=3)
trained model          precision=1.000  recall=1.000  f1=1.000  (test n=6, valid=3)
cross-val (train):     F1 0.800 +/- 0.400, recall 0.800
```

What this says, and what it does **not**:

- The **heuristic baseline** here is the existing `heuristic_priority` score
  turned into a classifier at its best-F1 threshold. It gets recall 1.0 but
  precision 0.5 because the catch-all false positives and the real
  missing-authorizer bug are *all* critical/high-confidence — the priority score
  cannot tell them apart.
- The **model** also sees `soft_404_similarity` (≈1.0 for the catch-all,
  ≈0.0 for the real bug) and the secret-confidence signal, so it separates them
  — precision 1.0 at the same recall 1.0.
- **Recall is the guardrail.** The trainer reports VALID recall for both and
  sets `recall_regressed` if the model's recall drops below the baseline; a
  model that bought precision by hiding real bugs is called out, not shipped.
- **Caveats:** the test split is tiny (n=6) and the cross-val F1 variance is
  large (±0.40) — this is a *proof of pipeline on a known target*, not evidence
  the model generalises to real-world traffic. Add more targets (demos,
  external apps, real feedback) before reading anything into absolute numbers.
- The production heuristic **pipeline** already suppresses most of these
  catch-all FPs via the soft-404 *filter* in the authz scanner. The model's
  contribution is to use that same signal as a **ranking** signal — keeping the
  finding (so recall is preserved) while de-prioritising it — rather than a hard
  drop.

## Enable it at scan time (opt-in, non-breaking)

```powershell
wily scan http://127.0.0.1:5000 --allow-local --ml-model ml/models/triage_model.joblib
```

When `--ml-model` is given, each finding gets `evidence['ml_valid_probability']`
and a `rank_reasons` entry noting the model touched the score, and the ordering
reflects a small, **bounded, sub-severity** boost (`±0.5` at most — the same
order as the heuristic impact boosts). The model **can re-rank and annotate; it
can never drop or hide a finding**, consistent with recall being the guardrail.

Fail-safe by design: if the `[ml]` extra is missing, the file is absent, or its
feature schema does not match this build, `wily scan` prints a warning and
falls back to heuristic ranking — it never aborts the scan. Without the flag,
ranking is heuristic-only and unchanged.

## Tests

- `tests/test_ml_features.py` — schema, scaling, missing-vs-zero, category
  one-hot, and the no-leakage guarantee.
- `tests/test_ml_dataset.py` — labeling, feedback override, write/read
  determinism, and the offline secret-source collection (no scikit-learn).
- `tests/test_ml_training.py` — trains on a tiny separable fixture, sane
  metrics, the recall guardrail, and joblib round-trip + schema-mismatch
  rejection (skipped without scikit-learn).
- `tests/test_ml_triage_wiring.py` — the no-op guarantee (no model → unchanged)
  and that an enabled model annotates and re-ranks without dropping a finding.
