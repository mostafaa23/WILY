# Wily enhancement roadmap

Organized from a batch of bug-bounty tooling ideas (JWT/token capture, IAM
clue extraction, cloud-enum automation, S3 write safety, OOB/SSRF). Each item
is marked **EXISTS**, **PARTIAL**, or **NEW** against the current code, and the
build work is grouped into phases meant to be done one per session.

The guiding constraint stays the same as the rest of Wily: **passive and
non-destructive by default**. Anything that could mutate a target or widen
reach stays behind an explicit, separate opt-in.

---

## What already exists (do not rebuild)

| Idea from the batch | Status | Where |
|---|---|---|
| Harvest JWTs from login responses, `Set-Cookie`, echoed headers, JS bundles | **EXISTS** | `recon/token_harvest.py` (`harvest_tokens`, auto-on in `scan_all`) |
| Seed `--token` from imported Burp/HAR traffic | **EXISTS** | `recon/traffic_import.py` |
| Weak HS256 secret recovery, alg:none, jku/x5u, kid | **EXISTS** | `scanners/jwt_tamper.py`, `scanners/jwt_secret.py` |
| interactsh-compatible OOB canary with `unique_id` correlation + polling | **EXISTS** | `core/oob_interaction.py` (`ExternalOOBClient`), `core/oob_canary.py` |
| Blind SSRF via canary, wired per-endpoint | **EXISTS** | `scanners/ssrf_imds.py` |
| Secret scan: AWS keys, bearer tokens, PEM private keys | **EXISTS** | `scanners/secret_scan.py` |
| Cloud-enum name permutations (two-part), AWS/Azure/GCP probe, auto hand-off to deep S3 | **EXISTS** | `recon/cloud_enum.py`, `scan_all._run_cloud_enum` |
| Three-part (lazys3-style) name combos `brand-env-service` | **EXISTS (new)** | `cloud_enum.build_combo_names`, `--cloud-enum-combos` |
| S3 writability check (ACL/policy-derived, read-only, never sends PUT) | **EXISTS** | `scanners/s3_bucket.py` (`confirm_writes`), follow-up `s3_permcheck` |
| Finding-driven follow-up chaining (authz→bola/jwt, public-s3→permcheck, creds→iam) | **EXISTS** | `risk/triggers.py`, `scan_all._run_followups` |

---

## Phase 1 — IAM / ARN clue extraction from JS, responses, and exposed IaC  **NEW**

**Why:** black-box recon can surface IAM role names, ARNs, and policy hints
without any AWS credentials — leaked in front-end JS, API error bodies, GraphQL
introspection, `/.well-known`, Swagger, or accidentally-exposed infra files
(`.tf`, `serverless.yml`, `cloudformation.{yml,json}`, `policy.json`). Today
`secret_scan.py` catches live *credentials* but not these *identifiers*.

**Build:**
- A new extractor (e.g. `scanners/iam_clue_scan.py`) with regexes for
  `arn:aws:(iam|sts|s3|lambda|ec2|...):...`, role names, `AssumeRole` snippets,
  and bucket/ARN references.
- Run it over the same corpus the secret scan already sees: discovered JS
  bundles, API/error response bodies, and any imported traffic.
- Parse exposed IaC files when discovery finds them (read-only).
- Emit `iam-clue-*` findings (informational/low unless corroborated).
- **Chain:** an IAM clue + a provided `--iam-file` should strengthen or seed
  `iam_privesc` analysis; add a rule in `risk/triggers.py`.

**Reference patterns:** LinkFinder / SecretFinder / JSFinder, trufflehog /
gitleaks ARN rules, nuclei ARN regex templates. **Do not** require live AWS
access (that is CloudMapper/PMapper/Pacu territory and out of scope for
black-box).

---

## Phase 2 — SSRF header-injection vector  **NEW (on existing canary)**

**Why:** the SSRF module injects into URL/host *parameters* but not into
request *headers*. Many SSRFs trigger only via `X-Forwarded-Host`,
`X-Forwarded-For`, `X-Real-IP`, `Client-IP`, `Referer`, `Host`, etc.

**Build:**
- Extend `scanners/ssrf_imds.py` to also inject `http://<unique_id>.<canary>`
  into a fixed list of SSRF-prone headers, reusing the existing
  `canary_server` / `unique_id` correlation and async polling — no new OOB
  infra.
- Each probe keeps a `unique_id` bound to `(asset, header, check_id)` so a
  returning hit identifies exactly which header fired, keeping false positives
  low.

**Reference:** SSRFmap, See-SURF for header/parameter handling; interactsh for
the callback side (already integrated).

---

## Phase 3 — Smarter cloud-enum automation  **PARTIAL**

**Why:** combos exist, but generation is still keyword-driven by the CLI. Make
it context-aware and budget-safe.

**Build:**
- **Seed extraction:** mine candidate keywords automatically from the domain,
  response bodies, JS bundles, and headers (company/product/env names) into the
  `seeds` list, instead of relying only on `--cloud-keyword`.
- **Auto-trigger:** when a scan observes `amazonaws.com`, `s3://`, AWS service
  names, or ARNs (ties into Phase 1), enable `cloud_enum` automatically even
  without the flag — gated and budget-capped.
- Keep the existing per-keyword permutation cap / `asyncio` concurrency bound so
  three-part combos can't blow up into millions of probes.

**Reference:** initstring/cloud_enum (permutations), sa7mon/S3Scanner (state
classification), nahamsec/lazys3 (seed→names).

---

## Phase 4 — Token/identity automation for BOLA  **NEW (heavier)**

**Why:** BOLA needs ≥2 working identities, supplied manually via `--identity`.
The batch proposes capturing them automatically.

**Build (incremental, each optional):**
- **Session/token pool from file:** **DONE** — `recon/token_pool.py` +
  `--token-pool <file>`. Reads a file of saved test identities (one
  `name=Header: value` or `name=<bare JWT>` per line, `#`/blank lines ignored;
  bare values must pass `is_valid_jwt`), verifies which still return 200 via a
  bounded read-only GET through the shared scope-enforcing `HttpEngine`, and
  auto-selects the first two live identities to feed `BolaTester`. Explicit
  `--identity` always wins and only tops up to two; tokens are never printed
  (redacted via `redact_jwt`). Test/lab tokens only.
- **Proxy / mitmproxy mode:** **PENDING** — optional man-in-the-middle to
  capture `Authorization: Bearer …` / `Set-Cookie` / login-response JWTs into
  the token pool. (Heavier dependency; deliberately deferred.)
- **Headless login automation (Playwright/Selenium):** **PENDING** — POST to
  `/api/login` with supplied test creds, scrape `access_token`/`id_token` from
  JSON, `localStorage`, `sessionStorage`, or cookies. (Heaviest; keep behind a
  flag, test creds only, never third-party production IdPs. Deliberately
  deferred.)

**Safety:** credentials handling must follow the existing redaction rules
(`redact_jwt`); never print raw tokens; test/lab credentials only.

---

## Phase 5 — S3 write confirmation: keep it safe  **DONE (strictly gated, default OFF)**

The batch proposes actually writing (`PUT`/upload) to confirm writability. This
**conflicts with Wily's non-destructive stance** and is risky on real
bug-bounty targets (could be destructive / out-of-scope / leave artifacts).

**Decision (unchanged default):** the current **ACL/policy-derived, read-only**
inference stays the default — it never sends a `PUT`. That path is byte-for-byte
unchanged and is still the only write signal unless the lab probe below is
explicitly turned on.

**Added — OPTIONAL lab-mode active write probe** (`scanners/s3_bucket.py`,
`lab_write` / `--s3-lab-write`): a single-marker `PUT`+`DELETE` confirmation that
is **OFF by default** and triple-gated. It can send a mutating request only when
**all three** independent gates hold at once (`_lab_write_allowed`):
1. env var `WILY_ALLOW_S3_WRITE=true`,
2. the `--s3-lab-write` flag is passed, AND
3. the bucket is inside an explicitly configured owned/lab bucket scope
   (`--scope-bucket`) — never a plain, unconfigured bug-bounty target.

If any gate is missing the probe does nothing (the scanner behaves exactly as
the read-only default) and the refusal is logged. When it fires it uploads the
smallest possible marker object with an unmistakable `wily-check-<random>.txt`
key, confirms the write, then **deletes it immediately** (best-effort `DELETE`
in a `finally`; a failed cleanup is surfaced in the finding). The resulting
`s3-bucket-public-writable` finding carries distinct evidence
(`check=write_permission_confirmed_active_lab_put`, `active_probe=true`,
`marker_key`, `put_status`, `delete_status`, `cleanup_ok`) marking it as an
active lab-mode confirmation, as opposed to the ACL-derived inference
(`check=write_permission_inferred_from_acl`). Wired through `app.py` and
`scan_all.py` (default OFF everywhere). Covered by tests proving the probe is
skipped when the env var is unset, when the flag is off, and when the scope is
not owned, and that only with all three gates does a (faked) `PUT`+`DELETE`
happen — including that a failed cleanup is reported.

---

## Suggested order

1. **Phase 1 (IAM/ARN clue extraction)** — new, well-grounded, no new deps, no
   safety issues, plugs into the existing secret-scan corpus and iam_privesc
   chain.
2. **Phase 2 (SSRF header injection)** — reuses the canary; small, high value.
3. **Phase 3 (cloud-enum automation)** — builds on the combos just added.
4. **Phase 4 (token/identity automation)** — start with the file-based pool.
5. **Phase 5 (S3 write)** — DONE: read-only stays the default; an optional,
   triple-gated (`WILY_ALLOW_S3_WRITE` + `--s3-lab-write` + owned `--scope-bucket`)
   lab-mode marker `PUT`/`DELETE` was added, default OFF.
