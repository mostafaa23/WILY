"""Live JWT auto-harvest: shared detection, response extraction, scope,
redaction, and the auto-token -> JWT-scanner hand-off.

All offline: a fake HTTP engine feeds canned responses; nothing is fetched.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import jwt as pyjwt

from wily.recon.token_harvest import (
    harvest_from_response,
    harvest_tokens,
    redact_jwt,
)
from wily.recon.traffic_import import find_jwts_in_text, is_valid_jwt, looks_like_jwt
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget

# A real, structurally valid JWT (header {"alg":"HS256","typ":"JWT"},
# payload {"sub":"1234","name":"Alice"}) - decodes to JSON on both segments.
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0IiwibmFtZSI6IkFsaWNlIn0"
    ".c2lnbmF0dXJlX2hlcmU"
)


@dataclass
class _Resp:
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 1.0
    url: str = ""


# --------------------------------------------------------------------------
# Shared detection: is_valid_jwt / find_jwts_in_text
# --------------------------------------------------------------------------


def test_is_valid_jwt_accepts_real_jwt():
    assert is_valid_jwt(VALID_JWT)
    assert looks_like_jwt(VALID_JWT)


def test_is_valid_jwt_rejects_non_jwt_dotted_strings():
    # Shape-only matches that are NOT real JWTs must be rejected by validation.
    assert not is_valid_jwt("a.b.c")
    assert not is_valid_jwt("1.2.3")  # a version string
    assert not is_valid_jwt("foo.bar.baz")
    # Three base64url-ish segments but the header is not JSON.
    assert not is_valid_jwt("aGVsbG8.d29ybGQ.c2ln")
    assert not is_valid_jwt("")
    assert not is_valid_jwt("not-a-token")


def test_find_jwts_in_body_cookie_and_js():
    body = f'{{"access_token": "{VALID_JWT}", "token_type": "Bearer"}}'
    cookie = f"session={VALID_JWT}; HttpOnly; Path=/"
    js = f'const T="{VALID_JWT}";export default T;'
    for blob in (body, cookie, js):
        found = find_jwts_in_text(blob)
        assert found == [VALID_JWT], blob


def test_find_jwts_rejects_version_and_dotted_noise():
    noise = "version 1.2.3 and a path a/b.c.d and foo.bar.baz everywhere"
    assert find_jwts_in_text(noise) == []


def test_find_jwts_dedupes_repeated_token():
    blob = f"{VALID_JWT} ... again {VALID_JWT}"
    assert find_jwts_in_text(blob) == [VALID_JWT]


# --------------------------------------------------------------------------
# harvest_from_response: headers (named) + body, with provenance
# --------------------------------------------------------------------------


def test_harvest_from_set_cookie_header_is_labelled():
    resp = _Resp(headers={"Set-Cookie": f"session={VALID_JWT}; HttpOnly"})
    harvested = harvest_from_response(resp, "http://t/login")
    assert len(harvested) == 1
    assert harvested[0].token == VALID_JWT
    assert harvested[0].source == "Set-Cookie header on http://t/login"


def test_harvest_from_body_is_labelled():
    resp = _Resp(text=f'{{"access_token":"{VALID_JWT}"}}')
    harvested = harvest_from_response(resp, "http://t/")
    assert len(harvested) == 1
    assert harvested[0].source == "response body on http://t/"


def test_harvest_same_token_in_header_and_body_returned_once():
    resp = _Resp(
        headers={"Authorization": f"Bearer {VALID_JWT}"},
        text=f"echo {VALID_JWT}",
    )
    harvested = harvest_from_response(resp, "http://t/x")
    assert [h.token for h in harvested] == [VALID_JWT]
    assert harvested[0].source.startswith("Authorization header")


def test_harvest_from_response_no_jwt():
    resp = _Resp(headers={"Set-Cookie": "session=opaque-not-a-jwt"}, text="<html>hi</html>")
    assert harvest_from_response(resp, "http://t/") == []


# --------------------------------------------------------------------------
# harvest_tokens: scope enforcement + budget
# --------------------------------------------------------------------------


class _FakeScope:
    def __init__(self, allowed_hosts: set[str]):
        self.allowed = allowed_hosts

    def is_in_scope(self, url: str) -> bool:
        from urllib.parse import urlparse

        return (urlparse(url).hostname or "") in self.allowed


class _FakeEngine:
    """Returns a canned response per URL and records every URL requested."""

    def __init__(self, by_url: dict[str, _Resp]):
        self.by_url = by_url
        self.requested: list[str] = []

    def request(self, method, url, headers=None, body=None):
        self.requested.append(url)
        return self.by_url.get(url, _Resp(status_code=404))


def test_harvest_tokens_respects_scope():
    in_scope = "http://target/login"
    out_scope = "http://evil.test/login"
    engine = _FakeEngine(
        {
            in_scope: _Resp(headers={"Set-Cookie": f"session={VALID_JWT}"}),
            out_scope: _Resp(text=f'{{"t":"{VALID_JWT}"}}'),
        }
    )
    scope = _FakeScope({"target"})
    harvested = harvest_tokens("http://target/", [in_scope, out_scope], scope, engine)

    # The out-of-scope endpoint is never even fetched (scope guard in prioritize).
    assert out_scope not in engine.requested
    assert [h.token for h in harvested] == [VALID_JWT]


def test_harvest_tokens_budget_caps_fetches():
    endpoints = [f"http://target/p{i}" for i in range(50)]
    engine = _FakeEngine({})  # everything 404s, no tokens
    scope = _FakeScope({"target"})
    harvest_tokens("http://target/", endpoints, scope, engine, max_fetch=5)
    assert len(engine.requested) == 5


# --------------------------------------------------------------------------
# redact_jwt: never leaks the raw token
# --------------------------------------------------------------------------


def test_redact_jwt_masks_token_but_shows_alg():
    label = redact_jwt(VALID_JWT)
    assert VALID_JWT not in label
    # Neither the payload nor signature segment leaks.
    assert VALID_JWT.split(".")[1] not in label
    assert VALID_JWT.split(".")[2] not in label
    assert "alg=HS256" in label
    assert "chars" in label


# --------------------------------------------------------------------------
# End-to-end: a harvested token enables the JWT scanner (alg:none fires)
# --------------------------------------------------------------------------


class _AlgNoneVulnerableEndpoint:
    """Fake endpoint: 401 with no auth, 200 for the real sample token, and
    200 for any ``alg:none`` forged token (the vulnerability)."""

    def __init__(self, sample_token: str):
        self.sample = sample_token

    def request(self, method, url, headers=None, body=None):
        auth = (headers or {}).get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _Resp(status_code=401)
        token = auth[len("Bearer ") :]
        try:
            alg = pyjwt.get_unverified_header(token).get("alg")
        except Exception:
            alg = None
        if str(alg).lower() == "none":
            return _Resp(status_code=200)
        if token == self.sample:
            return _Resp(status_code=200)
        return _Resp(status_code=401)


def test_harvested_token_enables_jwt_scanner_alg_none():
    # A token the way the demo /login would hand it out, in a Set-Cookie.
    secret = "demo-only-secret-not-for-production-32b"
    sample = pyjwt.encode({"sub": "demo", "role": "user"}, secret, algorithm="HS256")
    login_resp = _Resp(headers={"Set-Cookie": f"session={sample}"})
    harvest_engine = _FakeEngine({"http://target/": login_resp})
    scope = _FakeScope({"target"})

    harvested = harvest_tokens("http://target/", [], scope, harvest_engine)
    assert harvested, "the login response's Set-Cookie JWT should be harvested"
    token = harvested[0].token
    assert token == sample

    # Feed the harvested token straight into the JWT scanner (exactly what the
    # orchestrator's auto-token path does) and confirm it fires on alg:none.
    scanner = JwtTamperScanner(
        scope_manager=None, http_engine=_AlgNoneVulnerableEndpoint(sample)
    )
    findings = scanner.run(JwtTarget(url="http://target/api/profile", sample_token=token))
    categories = {f.category for f in findings}
    assert "jwt-tamper-alg-none" in categories
