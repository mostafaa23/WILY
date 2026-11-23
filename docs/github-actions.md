# Running Wily in GitHub Actions

Wily can run in a pipeline as a gate: scan an authorized target, fail the
build when something crosses a severity threshold, and upload the results to
GitHub Code Scanning so they show up in the repository's **Security** tab.

> **Authorization first.** This scans a live target. Only run it against a
> host you own or have explicit, written permission to test. Point it at your
> own staging/pre-production environment, never a third party's. The example
> uses a `TARGET` you control.

## Example workflow

```yaml
name: Security scan

on:
  workflow_dispatch:   # run it on demand
  schedule:
    - cron: "0 3 * * 1" # or on a schedule you choose

permissions:
  security-events: write   # required to upload SARIF to Code Scanning
  contents: read

jobs:
  wily:
    runs-on: ubuntu-latest
    env:
      TARGET: staging.your-own-domain.example   # a host YOU are authorized to test
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install wily
        run: pip install git+https://github.com/mostafaa23/wily.git

      - name: Scan
        run: wily scan "$TARGET" --format sarif -o wily-report.json --fail-on high

      - name: Upload results to Code Scanning
        if: always()   # upload even when the gate failed the build
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wily-report.sarif
```

Two details that matter:

- **`--fail-on high`** makes the `Scan` step exit non-zero when any finding is
  high or critical, which fails the job. Lower the threshold (`medium`) to be
  stricter, or drop the flag to report without ever failing.
- **`if: always()`** on the upload step means the SARIF is uploaded even after
  the gate fails, so the alerts still land in the Security tab instead of being
  lost with the failed job.

## Exit codes

`wily scan` uses these so a pipeline can branch on the outcome:

| code | meaning                                               |
|-----:|-------------------------------------------------------|
|  `0` | scan finished, nothing at or above `--fail-on` (or `--fail-on none`) |
|  `1` | gate failed — at least one finding at or above the threshold |
|  `2` | usage error or scan failure (bad option, unreadable input, or a crash in the scan itself) |

Code `1` means **only** the gate — a finding crossed the threshold. If the
scan itself breaks, the exit code is `2`, never `1`, so a red build from a
broken tool is never mistaken for a genuine security finding.

The threshold is applied **after** the triage layer, so de-duplicated and
baseline-filtered findings are what the gate sees. If you keep a feedback log
and pass `--feedback-store`, a finding you have marked a false positive with
`wily triage` will not fail the build:

```yaml
      - name: Scan with analyst feedback applied
        run: wily scan "$TARGET" --format sarif -o wily-report.json
             --fail-on high --feedback-store .wily/feedback.jsonl
```

## Note on this repository's own CI

The repository's own CI (`.github/workflows/ci.yml`) only runs the test suite.
It does **not** run a live scan — doing that needs an authorized target and
credentials that do not belong in a public workflow. The example above is for
**your** pipeline, against **your** target.
