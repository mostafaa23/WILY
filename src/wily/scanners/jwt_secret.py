"""Weak HS256 JWT signing-secret detection (local, bounded dictionary check).

When an app signs its JWTs with HMAC-SHA256 (``alg: HS256``), the whole
security of every token rests on one shared secret. A guessable secret
(``secret``, ``changeme``, a framework default, a short dictionary word)
means an attacker can mint a *valid* token for any user - no server bug
required. This module proves that specific weakness: given one real HS256
token, it recomputes the HMAC-SHA256 signature for each candidate in a small,
shipped wordlist and compares it to the token's own signature. A match is
cryptographic proof that the server's signing secret is that candidate.

Scope and safety (this is DETECTION, not an attack on anyone):
  * Purely **local CPU work** - no network, no brute force against a target.
  * **Bounded** by both a hard attempt cap and a wall-clock time cap, so it
    can never run unbounded even with a huge user-supplied wordlist.
  * The recovered secret is **never returned or logged raw** by the finding
    path - :func:`redact_secret` emits only its length, a fully masked form,
    and a SHA-256 fingerprint prefix (enough to correlate, not to reuse).

This is the same idea as ``c-jwt-cracker`` / ``jwt_tool``'s crack mode, but
reimplemented from the technique (HMAC recompute + compare) and deliberately
reduced to a bounded dictionary check - no incremental/GPU brute force.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from binascii import Error as BinasciiError
from dataclasses import dataclass

__all__ = [
    "COMMON_HS256_SECRETS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_SECONDS",
    "SecretRecoveryResult",
    "build_weak_hs256_finding",
    "recover_hs256_secret",
    "redact_secret",
]

# A small, bounded wordlist of secrets that are weak in practice: common
# placeholders, framework/tutorial defaults, and short dictionary words that
# repeatedly show up as real JWT signing secrets. Kept deliberately short -
# this is a "is the secret embarrassingly guessable" check, not a cracker.
COMMON_HS256_SECRETS: tuple[str, ...] = (
    "secret",
    "secret123",
    "secretkey",
    "secret_key",
    "mysecret",
    "mysecretkey",
    "supersecret",
    "supersecretkey",
    "topsecret",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "jwtSecret",
    "jwt-secret",
    "jwtkey",
    "jwt_key",
    "jwtpassword",
    "jsonwebtoken",
    "token",
    "tokensecret",
    "changeme",
    "change-me",
    "changethis",
    "password",
    "password1",
    "password123",
    "passw0rd",
    "admin",
    "administrator",
    "root",
    "default",
    "example",
    "test",
    "testkey",
    "test-secret",
    "testsecret",
    "dev",
    "development",
    "demo",
    "key",
    "private",
    "privatekey",
    "private_key",
    "signingkey",
    "signing_key",
    "signing-key",
    "hmac",
    "hmackey",
    "hmacsecret",
    "qwerty",
    "letmein",
    "iloveyou",
    "welcome",
    "12345",
    "123456",
    "1234567890",
    "0000",
    "abc123",
    # Widely copy-pasted tutorial/framework/library default strings.
    "your-256-bit-secret",
    "your_jwt_secret",
    "your-secret-key",
    "your_secret_key",
    "yoursecret",
    "shhhhh",
    "shh",
    "s3cr3t",
    "s3cret",
    "my_super_secret",
    "my-super-secret",
    "SuperSecretKeyForJWT",
    "ThisIsASecret",
    "insecure",
    "insecure-secret",
    "unsafe",
    "keyboard cat",
    "node-jsonwebtoken",
    "flask-jwt",
    "django-insecure",
)

# Hard caps. Even if a user supplies a huge --jwt-secret-wordlist, the check
# stops at whichever cap it hits first and reports that it was capped (so the
# result can never be mistaken for a clean "no weak secret" exhaustion).
DEFAULT_MAX_ATTEMPTS = 20_000
DEFAULT_MAX_SECONDS = 10.0


@dataclass(frozen=True)
class SecretRecoveryResult:
    """The outcome of one bounded weak-secret recovery attempt.

    ``recovered``/``secret`` carry the hit; everything else is honesty about
    how the search ran. ``exhausted`` means the whole wordlist was tried
    without a hit; ``capped`` means a cap stopped the search early (so a
    "not recovered" result is NOT a guarantee the secret is strong).
    """

    recovered: bool
    secret: str | None
    attempts: int
    elapsed_seconds: float
    exhausted: bool
    capped: bool


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _token_alg(token: str) -> str | None:
    """Return the ``alg`` from the token header without verifying anything,
    or None if the token is not a decodable JWT header."""
    try:
        header_seg = token.split(".")[0]
        header = json.loads(_b64url_decode(header_seg))
    except (ValueError, IndexError, UnicodeDecodeError, BinasciiError):
        return None
    alg = header.get("alg") if isinstance(header, dict) else None
    return str(alg) if alg is not None else None


def redact_secret(secret: str) -> dict:
    """A REDACTED-safe description of a recovered secret - never the raw value.

    Returns the length, a fully masked rendering (so nothing of the secret
    itself leaks into evidence, logs, or a report), and a short SHA-256
    fingerprint prefix so a reviewer can correlate "which secret" against
    their own wordlist without the value ever being reproduced.
    """
    raw = secret if isinstance(secret, str) else str(secret)
    length = len(raw)
    fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]
    return {
        "secret_length": length,
        "secret_masked": "•" * length,
        "secret_sha256_prefix": fingerprint,
    }


def recover_hs256_secret(
    token: str,
    *,
    extra_wordlist: list[str] | tuple[str, ...] | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> SecretRecoveryResult:
    """Try to recover an HS256 token's signing secret from a bounded wordlist.

    The built-in :data:`COMMON_HS256_SECRETS` are tried first, then any
    ``extra_wordlist`` the user supplied (e.g. via ``--jwt-secret-wordlist``).
    Each candidate is verified by recomputing the HMAC-SHA256 signature over
    the token's own ``header.payload`` signing input and comparing it, in
    constant time, to the token's signature segment. The search stops at the
    first match, or when it exhausts the wordlist, or when it hits the attempt
    or time cap - whichever comes first.

    Non-HS256 tokens (or anything that is not a decodable 3-segment JWT) return
    a ``recovered=False`` result immediately without consuming the budget.
    """
    started = time.monotonic()

    def _elapsed() -> float:
        return round(time.monotonic() - started, 4)

    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3 or _token_alg(token) != "HS256":
        return SecretRecoveryResult(False, None, 0, _elapsed(), False, False)

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        target_sig = _b64url_decode(signature_b64)
    except (ValueError, BinasciiError):
        return SecretRecoveryResult(False, None, 0, _elapsed(), False, False)

    # De-duplicate while preserving order: built-ins first, then user entries.
    candidates: list[str] = []
    seen: set[str] = set()
    for word in (*COMMON_HS256_SECRETS, *(extra_wordlist or ())):
        if not isinstance(word, str) or word in seen:
            continue
        seen.add(word)
        candidates.append(word)

    deadline = started + max(0.0, max_seconds)
    cap = max(0, max_attempts)
    attempts = 0

    for candidate in candidates:
        if attempts >= cap or time.monotonic() >= deadline:
            return SecretRecoveryResult(False, None, attempts, _elapsed(), False, True)

        attempts += 1
        computed = hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(computed, target_sig):
            return SecretRecoveryResult(True, candidate, attempts, _elapsed(), False, False)

    return SecretRecoveryResult(False, None, attempts, _elapsed(), True, False)


def build_weak_hs256_finding(asset: str, token: str, result: SecretRecoveryResult):
    """Build the ``jwt-weak-hs256-secret`` Finding for a recovered secret.

    Imported lazily so this module stays free of the scanner base import for
    the pure (networkless) crack path. The recovered secret is passed through
    :func:`redact_secret` - the raw value never enters the evidence dict.
    """
    from wily.scanners.base import Finding

    assert result.recovered and result.secret is not None
    evidence = {
        "technique": "weak_hs256_secret_dictionary",
        "algorithm": "HS256",
        "attempts": result.attempts,
        "wordlist_bounded": True,
        **redact_secret(result.secret),
    }
    return Finding(
        asset=asset,
        category="jwt-weak-hs256-secret",
        severity="critical",
        confidence=1.0,  # an HMAC match is cryptographic proof, not inference
        discovery_source="scanner",
        evidence=evidence,
        remediation=(
            "Rotate the JWT signing secret immediately and replace it with a "
            "high-entropy value (at least 256 bits of randomness, e.g. "
            "`secrets.token_urlsafe(32)`), stored outside source control. A "
            "guessable HS256 secret lets anyone forge a valid token for any "
            "user. Consider moving to asymmetric signing (RS256/ES256) so the "
            "signing key never leaves the issuer."
        ),
    )
