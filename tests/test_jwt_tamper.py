import time
from types import SimpleNamespace
from urllib.request import urlopen

import jwt
import pytest

from wily.core.oob_canary import OOBCanaryServer
from wily.core.scope_manager import ScopeManager
from wily.scanners.jwt_tamper import (
    JwtTamperScanner,
    JwtTarget,
    analyze_expiry_claims,
    build_x5u_injection_token,
    decode_unverified,
)


def _token(payload: dict) -> str:
    return jwt.encode(payload, "test-secret-for-jwt-expiry-tests-32-bytes", algorithm="HS256")


def test_analyze_expiry_claims_without_exp():
    result = analyze_expiry_claims(_token({"sub": "user"}))

    assert result == {
        "has_exp": False,
        "is_expired": None,
        "lifetime_seconds": None,
    }


def test_analyze_expiry_claims_expired_token():
    result = analyze_expiry_claims(_token({"exp": time.time() - 60}))

    assert result["has_exp"] is True
    assert result["is_expired"] is True
    assert result["lifetime_seconds"] < 0


def test_analyze_expiry_claims_future_expiry():
    result = analyze_expiry_claims(_token({"exp": time.time() + 3600}))

    assert result["has_exp"] is True
    assert result["is_expired"] is False
    assert 0 < result["lifetime_seconds"] <= 3600


def test_scanner_stops_if_endpoint_accepts_request_without_auth():
    class StubHttpEngine:
        def __init__(self):
            self.requests = []

        def request(self, **kwargs):
            self.requests.append(kwargs)
            return SimpleNamespace(status_code=200)

    http = StubHttpEngine()
    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"), http_engine=http
    )

    findings = scanner.run(
        JwtTarget(url="https://example.test", sample_token=_token({"sub": "user"}))
    )

    assert findings == []
    assert len(http.requests) == 2
    assert http.requests[0]["headers"] == {
        "Authorization": f"Bearer {_token({'sub': 'user'})}"
    }
    assert http.requests[1]["headers"] == {}


@pytest.mark.parametrize(
    ("payload", "expected_category"),
    [
        ({"sub": "user"}, "jwt-missing-exp-claim"),
        ({"exp": time.time() - 60}, "jwt-expired-token-accepted"),
        ({"exp": time.time() + 25 * 60 * 60}, "jwt-excessive-token-lifetime"),
    ],
)
def test_scanner_reports_expiry_claim_findings(payload, expected_category):
    class StubHttpEngine:
        def __init__(self):
            self.request_count = 0

        def request(self, **_kwargs):
            self.request_count += 1
            return SimpleNamespace(status_code=200 if self.request_count == 1 else 401)

    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"),
        http_engine=StubHttpEngine(),
    )
    findings = scanner.run(JwtTarget(url="https://example.test", sample_token=_token(payload)))

    expiry_findings = [
        finding for finding in findings if finding.category == expected_category
    ]
    assert len(expiry_findings) == 1
    assert expiry_findings[0].evidence["technique"] == "expiry_claim_analysis"


def test_build_x5u_injection_token_carries_the_canary_url():
    token = _token({"sub": "user"})
    forged = build_x5u_injection_token(token, "http://127.0.0.1:9/oob/abc/chain.pem")

    header, _payload = decode_unverified(forged)
    assert header["x5u"] == "http://127.0.0.1:9/oob/abc/chain.pem"
    assert header["alg"] == "RS256"


class _X5uVulnerableEngine:
    """Simulates a server vulnerable to x5u injection: when it sees a token
    carrying an ``x5u`` header, it fetches that URL (the SSRF), just as a real
    vulnerable verifier would to obtain the cert chain. Baseline (valid token)
    answers 200; a request with no auth answers 401. Only the x5u fetch touches
    the network, so the only OOB-confirmed finding is the x5u one."""

    def __init__(self, valid_token: str):
        self.valid_token = valid_token

    def request(self, *, headers=None, **_kwargs):
        auth = (headers or {}).get("Authorization", "")
        if not auth.startswith("Bearer "):
            return SimpleNamespace(status_code=401, text="")
        token = auth.removeprefix("Bearer ")
        if token == self.valid_token:
            return SimpleNamespace(status_code=200, text="")
        try:
            header, _payload = decode_unverified(token)
        except ValueError:
            return SimpleNamespace(status_code=401, text="")
        x5u = header.get("x5u")
        if x5u:
            # The vulnerable fetch: this is what the OOB canary records.
            try:
                with urlopen(x5u, timeout=3) as resp:
                    resp.read()
            except Exception:
                pass
        return SimpleNamespace(status_code=401, text="")


def test_x5u_injection_confirmed_via_oob_callback():
    valid_token = _token({"sub": "user"})
    engine = _X5uVulnerableEngine(valid_token)
    with OOBCanaryServer() as canary:
        scanner = JwtTamperScanner(
            scope_manager=ScopeManager("127.0.0.1", allow_local_targets=True),
            http_engine=engine,
        )
        findings = scanner.run(
            JwtTarget(
                url="http://127.0.0.1:5001/api/profile",
                sample_token=valid_token,
                canary_server=canary,
                oob_timeout=0.5,
            )
        )

    x5u = [f for f in findings if f.category == "jwt-tamper-x5u-injection"]
    assert len(x5u) == 1
    assert x5u[0].severity == "critical"
    assert x5u[0].evidence["oob_hit_confirmed"] is True
    assert x5u[0].evidence["technique"] == "x5u_header_injection"


def test_x5u_not_flagged_when_server_ignores_the_header():
    """A server that never fetches the x5u URL yields no OOB hit, so no x5u
    finding (no false positive without real evidence)."""

    class IgnoresX5u:
        def __init__(self, valid_token):
            self.valid_token = valid_token

        def request(self, *, headers=None, **_kwargs):
            auth = (headers or {}).get("Authorization", "")
            ok = auth == f"Bearer {self.valid_token}"
            return SimpleNamespace(status_code=200 if ok else 401, text="")

    valid_token = _token({"sub": "user"})
    with OOBCanaryServer() as canary:
        scanner = JwtTamperScanner(
            scope_manager=ScopeManager("127.0.0.1", allow_local_targets=True),
            http_engine=IgnoresX5u(valid_token),
        )
        findings = scanner.run(
            JwtTarget(
                url="http://127.0.0.1:5001/api/profile",
                sample_token=valid_token,
                canary_server=canary,
                oob_timeout=0.5,
            )
        )

    assert not [f for f in findings if f.category == "jwt-tamper-x5u-injection"]
