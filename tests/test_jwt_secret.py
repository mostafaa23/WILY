"""Weak HS256 signing-secret detection (local, bounded dictionary check)."""

from types import SimpleNamespace

import jwt as pyjwt

from wily.core.scope_manager import ScopeManager
from wily.scanners.jwt_secret import (
    COMMON_HS256_SECRETS,
    DEFAULT_MAX_ATTEMPTS,
    build_weak_hs256_finding,
    recover_hs256_secret,
    redact_secret,
)
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget


def _hs256(payload: dict, secret: str) -> str:
    return pyjwt.encode(payload, secret, algorithm="HS256")


def test_recovers_a_weak_builtin_secret():
    token = _hs256({"sub": "user", "role": "admin"}, "secret")
    result = recover_hs256_secret(token)

    assert result.recovered is True
    assert result.secret == "secret"
    assert result.attempts >= 1
    assert result.capped is False


def test_recovers_a_secret_only_present_in_extra_wordlist():
    token = _hs256({"sub": "user"}, "org-specific-weak-2024")
    # Not in the built-in list -> only found because the user supplied it.
    assert recover_hs256_secret(token).recovered is False

    result = recover_hs256_secret(token, extra_wordlist=["nope", "org-specific-weak-2024"])
    assert result.recovered is True
    assert result.secret == "org-specific-weak-2024"


def test_strong_secret_is_not_recovered_and_marked_exhausted():
    token = _hs256({"sub": "user"}, "G9!xQ27w-unguessable-random-7f3a9c2e1b")
    result = recover_hs256_secret(token)

    assert result.recovered is False
    assert result.secret is None
    assert result.exhausted is True
    assert result.capped is False


def test_attempt_cap_is_honored():
    token = _hs256({"sub": "user"}, "still-not-in-any-list-zzz")
    huge = [f"candidate-{i}" for i in range(100_000)]
    result = recover_hs256_secret(token, extra_wordlist=huge, max_attempts=50)

    assert result.recovered is False
    assert result.capped is True
    # Never ran past the cap, even with a 100k-entry wordlist.
    assert result.attempts <= 50


def test_time_cap_is_honored():
    token = _hs256({"sub": "user"}, "still-not-in-any-list-zzz")
    huge = [f"candidate-{i}" for i in range(500_000)]
    # A zero-second budget stops almost immediately; never exhausts the list.
    result = recover_hs256_secret(token, extra_wordlist=huge, max_seconds=0.0)

    assert result.recovered is False
    assert result.capped is True
    assert result.attempts < len(huge)


def test_non_hs256_token_is_skipped_without_consuming_budget():
    # alg:none token -> not HS256, so the check does not run.
    header = pyjwt.utils.base64url_encode(b'{"alg":"none","typ":"JWT"}').decode()
    body = pyjwt.utils.base64url_encode(b'{"sub":"user"}').decode()
    none_token = f"{header}.{body}."

    result = recover_hs256_secret(none_token)
    assert result.recovered is False
    assert result.attempts == 0


def test_malformed_token_does_not_raise():
    for bad in ["", "not-a-jwt", "a.b", "a.b.c.d", None]:
        result = recover_hs256_secret(bad)  # type: ignore[arg-type]
        assert result.recovered is False


def test_redaction_never_exposes_the_raw_secret():
    secret = "changeme"
    red = redact_secret(secret)

    assert red["secret_length"] == len(secret)
    assert secret not in str(red)
    assert set(red["secret_masked"]) == {"•"}
    assert len(red["secret_masked"]) == len(secret)
    # Fingerprint is a short SHA-256 prefix, not the value.
    assert len(red["secret_sha256_prefix"]) == 12
    assert secret not in red["secret_sha256_prefix"]


def test_finding_is_critical_and_fully_redacted():
    token = _hs256({"sub": "user"}, "password123")
    result = recover_hs256_secret(token)
    assert result.recovered

    finding = build_weak_hs256_finding("https://api.example.test/me", token, result)

    assert finding.category == "jwt-weak-hs256-secret"
    assert finding.severity == "critical"
    assert finding.confidence == 1.0
    # The raw secret appears nowhere in the finding (evidence or remediation).
    blob = str(finding.to_dict())
    assert "password123" not in blob
    assert finding.evidence["secret_length"] == len("password123")
    assert finding.evidence["algorithm"] == "HS256"


def test_builtin_wordlist_is_bounded():
    # Sanity: the shipped list stays small and well under the attempt cap, so
    # the default run is cheap and can never be mistaken for a brute forcer.
    assert 0 < len(COMMON_HS256_SECRETS) < 500
    assert len(COMMON_HS256_SECRETS) < DEFAULT_MAX_ATTEMPTS


class _JwtStubEngine:
    """Baseline (valid token) -> 200; everything else (no-auth, forged) -> 401,
    so the only finding a weak-but-otherwise-sound token yields is the local
    weak-secret one (plus the passive missing-exp analysis)."""

    def __init__(self, valid_token: str):
        self.valid_token = valid_token
        self.requests = 0

    def request(self, *, headers=None, **_kwargs):
        self.requests += 1
        auth = (headers or {}).get("Authorization", "")
        if auth == f"Bearer {self.valid_token}":
            return SimpleNamespace(status_code=200, text="")
        return SimpleNamespace(status_code=401, text="")


def test_scanner_emits_weak_secret_finding_end_to_end():
    token = _hs256({"sub": "user"}, "letmein")
    engine = _JwtStubEngine(token)
    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"), http_engine=engine
    )

    findings = scanner.run(JwtTarget(url="https://example.test/me", sample_token=token))

    weak = [f for f in findings if f.category == "jwt-weak-hs256-secret"]
    assert len(weak) == 1
    assert weak[0].severity == "critical"
    assert "letmein" not in str(weak[0].to_dict())  # raw value never leaks


def test_scanner_skips_weak_secret_check_when_disabled():
    token = _hs256({"sub": "user"}, "letmein")
    engine = _JwtStubEngine(token)
    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"), http_engine=engine
    )

    findings = scanner.run(
        JwtTarget(
            url="https://example.test/me", sample_token=token, check_weak_secret=False
        )
    )
    assert not [f for f in findings if f.category == "jwt-weak-hs256-secret"]
