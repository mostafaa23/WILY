# Triage benchmark

Does Wily's triage layer actually cut false positives, or is that just a
claim? This benchmark answers it with a number, on a target whose every
vulnerability is known in advance.

## What it measures

`vulnerable_benchmark_api.py` is a small local API with a declared ground
truth (`GROUND_TRUTH` in that file):

- **one genuine bug** — `/orders/4215` returns real order data to an
  unauthenticated `DELETE` (a true missing-authorizer finding Wily *should*
  report), and
- **a realistic false-positive source** — a catch-all route (an SPA /
  default-integration fallback) that answers `200` with the same generic
  body for every undefined path. A scanner that treats "`200` with no auth
  header = leak" flags each probed-but-undefined path as a missing
  authorizer, even though they all resolve to one generic page that leaks
  nothing.

`run_benchmark.py` scans every path twice and scores the findings against
the ground truth:

- **triage OFF** — the differential soft-404 baseline disabled (the naive
  `200 = leak` behaviour), and
- **triage ON** — the soft-404 baseline enabled, so a candidate leak whose
  body matches "what a missing resource looks like here" is dropped.

## Result

Run it yourself:

```bash
python benchmark/run_benchmark.py
```

Numbers from an actual run (`results.json` is written each time; these are
not hard-coded):

| metric            | triage OFF | triage ON |
|-------------------|-----------:|----------:|
| findings          |          7 |         2 |
| true positives    |          2 |         2 |
| false positives   |          5 |         0 |
| precision         |       0.29 |      1.00 |
| real vulns found  |        1/1 |       1/1 |

The soft-404 baseline removed all 5 false positives and left precision at
1.00, **without** dropping the one real vulnerability — recall stayed `1/1`.
That last column is the honest guardrail: a filter that just deletes
findings would raise precision by hurting recall, and this makes that
visible instead of hiding it.

## Honest limitations

- **This is a constructed target, not a field study.** It isolates one
  well-documented false-positive pattern (the generic catch-all) so the
  effect is measurable in a few seconds. The 0.29 → 1.00 jump is the size of
  the effect *on this pattern*; it is not a promise of the same number on an
  arbitrary real API, where the FP mix is different.
- **The baseline is body-based, so it only helps methods that return a
  body.** The benchmark scans `GET` for exactly this reason: a `HEAD` 200
  carries no body, so it can neither leak data nor be compared against the
  baseline. Body-less responses are outside what this check can reason
  about.
- **It covers the differential soft-404 baseline specifically.** The other
  triage pieces (contextual risk scoring, the sensitivity scorer,
  endpoint-aware dedup, the feedback loop) change ranking and grouping
  rather than removing findings outright, and are covered by their own unit
  tests rather than this precision metric.
