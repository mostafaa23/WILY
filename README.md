# Wily

[![CI](https://github.com/mostafaa23/wily/actions/workflows/ci.yml/badge.svg)](https://github.com/mostafaa23/wily/actions/workflows/ci.yml)

> Cloud-native, cloud security scanner.

Wily starts from a domain you're authorized to test, discovers assets and
cloud services, routes each one to the appropriate checks, and produces a
unified report (JSON / HTML / SARIF) with evidence and a severity &
confidence rating for every finding.

## What it does

Wily bundles eight detection engines behind a single `wily scan` command and
also exposes several of them as focused standalone subcommands:

1. **JWT Tampering** — algorithm confusion, `alg:none`, weak-secret and
   signature-bypass checks against a sample token.
2. **API Auth Bypass** — broken-authorization probes, plus CORS
   misconfiguration and stage/environment inconsistency detection.
3. **BOLA / cross-tenant access** — compares two or more identities to find
   objects one tenant can reach that belong to another.
4. **IAM privilege escalation** — offline analysis of an AWS
   `get-account-authorization-details` export (passrole, trust-policy abuse,
   resource hijack, and related escalation paths).
5. **Cloud SSRF / IMDS** — makes the target fetch internal cloud metadata
   endpoints to reveal server-side request forgery.
6. **Endpoint & parameter discovery** — OpenAPI, JavaScript and wordlist-based
   asset discovery feeding the scan queue.
7. **Cloud storage enumeration** — `cloud_enum`-style AWS S3 / Azure Blob /
   GCP bucket name generation and probing, with automatic hand-off of live
   S3 buckets to the deep bucket-misconfiguration scan.
8. **Triage, ranking & reporting** — endpoint-aware de-duplication, contextual
   risk scoring driven by the actual evidence, a sensitivity scorer that tells
   a real leak from a public catalog response, an analyst feedback loop, and
   unified JSON, HTML and SARIF report writers.

## Install

The project is published to PyPI as **`wily-scanner`** (the `wily` name was
already taken). The installed command is still **`wily`**.

**[pipx](https://pipx.pypa.io)** is recommended because it installs the `wily`
command into an isolated environment and puts it on your `PATH`:

```bash
pipx install wily-scanner
```

Or with plain `pip` (ideally inside a virtual environment):

```bash
pip install wily-scanner
```

The machine-learning triage layer is an optional extra:

```bash
pip install "wily-scanner[ml]"
```

To install the latest unreleased code straight from source instead:

```bash
pipx install git+https://github.com/mostafaa23/wily.git
```

Either way you get the **`wily`** command available in your terminal:

```bash
wily --version
wily -h
```

Python 3.11 or 3.12 is required.

## Usage

```bash
# See every command and global option
wily -h
```

```bash
# The full bundle, automatically: discovery + auth bypass + CORS + SSRF
wily scan example.com -o report.json

# Add JWT Tampering (needs a valid sample token)
wily scan example.com --token eyJhbGciOi... -o report.json

# Add BOLA (needs at least two identities to compare)
wily scan example.com \
  --identity tenant_a="Bearer xyz" \
  --identity tenant_b="Bearer abc"

# Analyze an AWS IAM authorization-details export for privilege escalation
wily scan --iam-file authorization-details.json

# Produce HTML and SARIF alongside JSON
wily scan example.com -o report.json --format html,sarif
```

Each engine is also available on its own:

```bash
wily jwt <url> --token TOKEN_VALUE   # JWT Tampering only
wily authz <url>                     # API Auth Bypass only
wily iam authorization-details.json  # IAM privilege-escalation only
wily ssrf <url> --param url          # IMDS cloud SSRF only
wily discover <domain>               # Endpoint discovery only, no scanning
wily triage report.json --list       # Review/record verdicts on a past report
```

Run `wily <command> -h` for the full set of options on any subcommand.

## Triage: cutting false positives

The weakest part of any black-box scanner is not finding things — it is being
wrong about them. Wily pushes back on that in four places, and every
adjustment it makes is written into the report as a reason, never applied
silently:

- **Differential baselines.** A candidate "leak" is compared against what the
  target returns for an authorized request, for a denied one, and for a
  resource that does not exist. A `200 OK` whose body matches the generic
  catch-all page is dropped instead of reported (`wily authz --soft-404-url`).
- **Evidence-based risk.** Severity boosts come from what was actually
  observed — a live cloud credential outranks a generic token-shaped string,
  and a BOLA hit on an object confirmed to belong to another tenant outranks a
  seeded guess — rather than from a fixed per-category number.
- **Sensitivity scoring.** Responses are scored for whether they carry real
  sensitive material (cloud keys, JWTs, account-shaped records) or just look
  like a public listing.
- **Endpoint-aware de-duplication.** `/invoices/1` … `/invoices/100` collapse
  into one finding on `/invoices/{id}`, while genuine version prefixes
  (`/v1/`, `/v2/`) are left alone.

### Does it work? (benchmark)

On a target with a known ground truth — one real authorization bug plus a
generic catch-all that a naive `200 = leak` scanner reports as five separate
missing-authorizer findings — the differential soft-404 baseline gives:

| metric          | triage OFF | triage ON |
|-----------------|-----------:|----------:|
| false positives |          5 |         0 |
| precision       |       0.29 |      1.00 |
| real bug found  |        1/1 |       1/1 |

The false positives are removed without losing the real vulnerability. These
numbers come from an actual scan, not an estimate — reproduce them with
`python benchmark/run_benchmark.py`, and see [benchmark/](benchmark/) for the
method and its honest limitations (it isolates one well-documented FP pattern;
it is not a promise of the same number on an arbitrary API).

### Feedback loop

Your verdicts are worth keeping. `wily triage` records them against a stable
hash of each finding, so a decision survives a re-scan even when the object id
in the URL changes:

```bash
# Review the findings in a report, with any verdict you recorded earlier
wily triage wily-report.json --list

# Mark row 2 as a real finding and row 5 as a false positive
wily triage wily-report.json --valid 2 --fp 5 --note "confirmed in staging"

# Carry those verdicts into the next scan's report
wily scan example.com -o report.json --feedback-store wily-feedback.jsonl
```

Decisions append to a local JSONL log (`wily-feedback.jsonl` by default).
Nothing is uploaded anywhere, and no model is trained today — the log is the
labeled data a trained classifier would need, which is why it is worth
collecting from the first scan.

## CI gate

`wily scan --fail-on <level>` turns Wily into a pipeline gate: it exits
non-zero when a finding is at or above the chosen severity, so a build can
stop on it instead of the scan only being run by hand.

```bash
# Fail the build on any high or critical finding
wily scan staging.example.com --format sarif -o report.json --fail-on high
```

| exit code | meaning |
|----------:|---------|
| `0` | nothing at or above the threshold (or `--fail-on none`, the default) |
| `1` | gate failed — a finding crossed the threshold (also used for run errors) |
| `2` | invalid command usage |

The threshold is applied **after** the triage layer, and a finding you marked
a false positive via `--feedback-store` never fails the build. With several
domains, the build fails if any one of them crosses the threshold, and the
failing domains are named.

Wily writes SARIF (`--format sarif`) ready for **GitHub Code Scanning**, with a
stable per-finding fingerprint so re-scans update the same alert instead of
opening new ones. A complete, copy-pasteable GitHub Actions example (scan,
`--fail-on`, and `upload-sarif` with `if: always()`) is in
[docs/github-actions.md](docs/github-actions.md).

## Safety

Wily is a **detection-oriented** scanner intended for authorized testing only.

- It enforces a target **scope** and refuses out-of-scope hosts; local
  addresses require an explicit `--allow-local`.
- Cloud-storage and S3 checks are **read-only by default** — Wily reads
  bucket ACLs/policies and infers write exposure from them; it does not issue
  `PUT`/`DELETE` unless the optional active write probe below is explicitly
  enabled.
- Genuinely offensive behaviors are opt-in and clearly flagged: write-method
  authorization probes (`--no-destructive` to disable), SSRF/IMDS checks
  (`--no-owned-infra` to disable), blind SSRF (`--blind`), and an active S3
  write-confirmation probe (`--s3-lab-write`, OFF by default, also requires
  `WILY_ALLOW_S3_WRITE=true`) that uploads and immediately deletes one marker
  object to confirm write access - it is **not** limited to a declared
  owned/lab bucket scope, so only enable it against buckets you control.
- Captured secrets in reports are **redacted by default**.

Only run Wily against systems you own or have explicit, written permission to
test.

## License

Released under the [MIT License](LICENSE).
