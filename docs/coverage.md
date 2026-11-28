# Wily detection coverage

The complete list of what Wily currently detects, generated from the live
code (`src/wily/scanners/` and `src/wily/templates/rules/`). This is the
"what can we do today" baseline: use it to see the full surface at a glance,
to avoid claiming coverage we don't have, and as the reference point for
finding gaps and tracking new vulnerabilities.

Every finding is emitted with a stable `category` string (the identifiers
below), a severity, a confidence, and evidence. The triage/ML layer
(`src/wily/risk/ml/`) then de-duplicates, re-ranks, and scores these before
they reach a report.

> **Safety:** every check is **read-only** (GET/analysis only — never a
> destructive write) unless a `--confirm-*` flag is explicitly passed.

## Summary

| Area | Scanner / rule | Distinct checks |
|------|----------------|----------------:|
| Authorization bypass (API Gateway / serverless) | `authz_bypass.py` | 6 |
| Broken Object Level Authorization (BOLA / IDOR) | `bola.py` | 1 (3 grounding modes) |
| JWT / IdP tampering | `jwt_tamper.py` + `jwt_secret.py` | 11 |
| S3 bucket misconfiguration | `s3_bucket.py` | 4 |
| Multi-cloud storage exposure | `cloud_storage.py` | 4 |
| Cloud IMDS SSRF | `ssrf_imds.py` | 2 |
| IAM privilege escalation | `iam_privesc.py` | 15 techniques |
| Secret / credential exposure | `secret_scan.py` | 10 kinds |
| Subdomain / cloud takeover | `takeover.py` | 9 services |
| Session fixation | `session_fixation.py` | 1 |
| Account enumeration (timing) | `timing_enum.py` | 1 |
| TLS / certificate configuration | `tls_config.py` | 6 |
| Token / session-ID randomness | `token_entropy.py` | 3 |
| HTTP security headers | `security_headers.py` | 1 (grouped per origin) |
| Declarative YAML rules | `templates/rules/` | 3 |

---

## 1. Authorization bypass — `scanners/authz_bypass.py`

Serverless / API Gateway authorizer mistakes. Maps to **OWASP API5:2023 —
Broken Function Level Authorization**.

| `category` | What it catches |
|------------|-----------------|
| `authz-bypass-missing-authorizer` | A method answers with data and no auth header is required |
| `authz-bypass-method-inconsistency` | Some methods on a resource are protected, others (e.g. DELETE) are not |
| `authz-bypass-stage-inconsistency` | One deployment stage (`/dev`, subdomain) drops the authorizer another stage enforces |
| `authz-bypass-authorizer-fail-open` | Rejects a missing token (401) but accepts any garbage token (200) |
| `authz-bypass-cors-origin-reflection` | Reflects any `Origin` back with `Access-Control-Allow-Credentials: true` |
| `authz-bypass-cors-wildcard-with-credentials` | `Access-Control-Allow-Origin: *` together with credentials |

## 2. BOLA / IDOR — `scanners/bola.py`

Cross-identity object access in multi-tenant APIs. Maps to **OWASP
API1:2023 — Broken Object Level Authorization**. Each `BolaFinding` carries
a **grounding** so a reviewer knows how strong the evidence is:

- `observed` — the owner identity came from watched traffic (strongest)
- `seeded` — the owner was inferred from an identity's own JWT claim
- `unowned` — no known owner; comparing whichever identities responded

## 3. JWT / IdP tampering — `scanners/jwt_tamper.py`

Maps to **OWASP API2:2023 — Broken Authentication**.

| `category` | What it catches |
|------------|-----------------|
| `jwt-tamper-alg-none` | Server trusts `alg: none` and skips signature verification |
| `jwt-tamper-signature-stripped` | Accepts a token with the signature removed |
| `jwt-tamper-rs256-hs256-confusion` | RS256→HS256 algorithm-confusion (public key used as HMAC secret) |
| `jwt-tamper-kid-null-key` | `kid` header coerced to a null/empty signing key |
| `jwt-tamper-jku-injection` | `jku` header points to an attacker-controlled key set (OOB-confirmed) |
| `jwt-tamper-x5u-injection` | `x5u` header points to an attacker-controlled cert chain (OOB-confirmed) |
| `jwt-tamper-jwk-injection` | Embedded `jwk` header key is trusted |
| `jwt-weak-hs256-secret` | HS256 signing secret recovered from a bounded weak-secret wordlist |
| `jwt-missing-exp-claim` | Token has no expiry claim |
| `jwt-expired-token-accepted` | An already-expired token is still accepted |
| `jwt-excessive-token-lifetime` | Token lifetime far longer than is safe |

**Weak HS256 secret (`jwt-weak-hs256-secret`).** When an HS256 token is
available (`--token`, auto-harvested, or supplied to `wily jwt`), Wily tries to
recover the signing secret **locally** by recomputing the HMAC-SHA256
signature for each candidate in a small, shipped wordlist of common/weak
secrets and framework defaults — a match is cryptographic proof the secret is
guessable. It is **bounded** (a hard attempt cap *and* a wall-clock time cap,
so it never runs unbounded even with a huge `--jwt-secret-wordlist <file>`),
**networkless** (pure local CPU — not a brute-force against any target), and
the recovered secret is **never printed raw**: evidence carries only its
length, a fully masked form, and a short SHA-256 fingerprint.

**`x5u` injection (`jwt-tamper-x5u-injection`).** The X.509-cert-chain sibling
of `jku`: a forged token's `x5u` header points at a canary URL; a server that
fetches it is flagged on the **out-of-band callback** (SSRF via `x5u`), the
same canary/owned-infra wiring the `jku` and blind-SSRF checks use.

## 4. S3 bucket misconfiguration — `scanners/s3_bucket.py`

Read-only (GET only). Maps to **OWASP API8:2023 — Security
Misconfiguration**.

| `category` | What it catches |
|------------|-----------------|
| `s3-bucket-public-acl` | Bucket ACL grants public access |
| `s3-bucket-public-listing` | Anonymous listing of bucket contents |
| `s3-bucket-public-object` | Individual objects readable anonymously |
| `s3-bucket-public-writable` | Bucket accepts anonymous writes (reported, not performed) |

## 5. Multi-cloud storage — `scanners/cloud_storage.py`

AWS S3 / Google Cloud Storage / Azure Blob enumeration and open-access
detection.

| `category` | What it catches |
|------------|-----------------|
| `cloud-storage-s3-open` | Open AWS S3 bucket |
| `cloud-storage-gcp-bucket-open` | Open Google Cloud Storage bucket |
| `cloud-storage-azure-account` | Discoverable Azure storage account |
| `cloud-storage-azure-blob-open` | Open Azure Blob container |

## 6. Cloud IMDS SSRF — `scanners/ssrf_imds.py`

Maps to **OWASP API7:2023 — Server-Side Request Forgery**.

| `category` | What it catches |
|------------|-----------------|
| `cloud-ssrf-blind` | Blind SSRF confirmed via out-of-band canary callback |
| `cloud-ssrf-imds-v2-token-bypass` | IMDSv2 token handling that still exposes metadata |

**Out-of-band confirmation (local *and* remote).** Blind SSRF, `jku` and `x5u`
are confirmed by a real out-of-band callback, not just a status code. The
default canary binds loopback (`127.0.0.1`), so it only confirms against
**local** targets. For **remote** targets there are two opt-in, owned-infra-
gated paths (both preserve `--confirm-owned-infra`; no public server is
shipped — the user supplies the endpoint):

- `--oob-server <url>` — register with your own interactsh-compatible server
  (`ExternalOOBClient`) and poll it for callbacks; no inbound listener needed.
- `--oob-bind <host:port>` + `--oob-public-url <url>` — bind the self-hosted
  canary to a reachable interface and advertise the externally reachable URL.

## 7. IAM privilege escalation — `scanners/iam_privesc.py`

Analyses `aws iam get-account-authorization-details` output for known
escalation paths. Maps to **OWASP API5 / cloud IAM**.

- `iam-privesc-self-mutation` — a principal that can rewrite its own permissions
- `iam-privesc-<technique>` — 14 classic escalation techniques, including:
  `AddUserToGroup`, `AttachUserPolicy`, `AttachRolePolicy`,
  `AttachGroupPolicy`, `CreateAccessKey`, `CreateLoginProfile`,
  `UpdateLoginProfile`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`,
  `PassRole`, `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`,
  `UpdateAssumeRolePolicy`.

## 8. Secret / credential exposure — `scanners/secret_scan.py`

Pattern-matches 10 credential kinds in responses, and flags live cloud
credentials (`is_live_cloud_credential`). Secrets are **redacted/masked** by
default.

`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`,
`private_key`, `github_token`, `slack_token`, `google_api_key`, `jwt`,
`bearer_token`, `generic_api_key`.

## 9. Subdomain / cloud takeover — `scanners/takeover.py`

Dangling DNS pointing at an unclaimed provider resource. 9 providers:
`aws-s3`, `github-pages`, `heroku`, `fastly`, `azure`, `cloudfront`,
`shopify`, `bitbucket`, `pantheon`.

## 10. Session fixation — `scanners/session_fixation.py`

`session-fixation` — session ID is not rotated after authentication.
Maps to **OWASP API2 / OWASP A07**.

## 11. Timing account enumeration — `scanners/timing_enum.py`

`timing-account-enumeration` — response-time differences reveal whether an
account exists.

## 12. TLS / certificate configuration — `scanners/tls_config.py`

| `category` | What it catches |
|------------|-----------------|
| `tls-cert-expired` | Certificate already expired |
| `tls-cert-expiring-soon` | Certificate near expiry |
| `tls-cert-hostname-mismatch` | Certificate does not match the host |
| `tls-cert-self-signed` | Self-signed certificate |
| `tls-weak-protocol` | Weak/deprecated TLS protocol accepted |
| `tls-mozilla-config-level` | Configuration below Mozilla's recommended level |

## 13. Token / session-ID randomness — `scanners/token_entropy.py`

Uses NIST SP 800-90B min-entropy.

| `category` | What it catches |
|------------|-----------------|
| `token-predictable-sequential` | Tokens are sequential / predictable |
| `token-collision` | Repeated (colliding) tokens observed |
| `token-low-entropy` | Token randomness below threshold |

## 14. HTTP security headers — `scanners/security_headers.py`

`security-misconfig-headers` — one grouped finding per origin (a single
read-only GET). Maps to **OWASP A02 — Security Misconfiguration**. Evidence
lists:

- `missing` — `Content-Security-Policy`, `X-Frame-Options` (satisfied by CSP
  `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, and `Strict-Transport-Security` on HTTPS responses.
  The document-only headers are checked only on HTML responses.
- `weak` — CSP `script-src`/`default-src` allowing `'unsafe-inline'` (without
  nonce/hash), `'unsafe-eval'` or `*`; report-only CSP; non-`nosniff`
  `X-Content-Type-Options`; `Referrer-Policy: unsafe-url`; HSTS `max-age`
  under 180 days.
- `info_disclosure` — `Server` / `X-Powered-By` with a version, and the
  ASP.NET version headers.

Severity is `medium` when CSP, HSTS, frame protection or nosniff is missing or
weak, otherwise `low`.

---

## Declarative YAML rules — `templates/rules/`

The newer, code-free way to add checks (run with `wily scan --rules`).
Validate them with `wily templates validate`.

| Rule | Status |
|------|--------|
| `cors/cors-origin-reflection` | Runs end-to-end; de-duplicates against the code scanner |
| `secrets/secret-exposure-response-body` | Runs (regex over response body) |
| `ssrf/imds-ssrf-candidate` | Schema-valid; needs out-of-band (interactsh-style) infra to fire |

---

## Known gaps / not yet covered

These are deliberately listed so coverage claims stay honest:

- **Injection** (SQLi, NoSQLi, command, template) — not covered.
- **Mass assignment / BOPLA** (OWASP API3) — not covered.
- **Rate limiting / unrestricted resource consumption** (OWASP API4) — not covered.
- **GraphQL-specific** issues — not covered.
- **Business-logic flaws** — deferred by design (the planned LLM-agent layer).
- Most detection logic is **code-based**; the YAML rule library is new and
  small (3 rules). Growing it is the main path to cheap new coverage.

## Keeping up with new vulnerabilities

The process for staying current:

1. **Pick the technologies we already touch** (API Gateway, Lambda
   authorizers, JWT libraries, S3/GCS/Azure storage, IMDS, IAM) and review
   recent CVEs / advisories for each.
2. **Classify each new issue**: is it a new *category* under an existing
   scanner, a whole new scanner, or a YAML rule?
3. **Prefer a YAML rule** when the check is request + matcher shaped — it is
   the cheapest to add and needs no Python.
4. **Add a test and a demo target** for every new check (follow the existing
   `tests/` + `demo/` pattern) so coverage is proven, not claimed.
5. Re-generate this document when checks change.

The `vulnerability-research-enrichment` skill automates steps 1–4: it audits
this project, researches current vulnerabilities for the technologies above,
finds coverage gaps, and adds tested rules in the existing format.

## Triage: heuristic by default, optionally trainable

Finding prioritisation is heuristic by default (`src/wily/risk/ml/ranker.py` +
`sensitivity.py` + `dedup.py`). An **optional** trained classifier can re-rank
findings using the same signals, bootstrapped from the benchmark/demo targets
whose ground truth we declare — see [docs/ml.md](ml.md) for how to reproduce the
dataset, train the model, and enable it with `wily scan --ml-model`. It is off
unless enabled, never drops a finding, and keeps recall as the guardrail.
