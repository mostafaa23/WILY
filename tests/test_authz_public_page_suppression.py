"""Tests for the public-page / catch-all false-positive suppression in
AuthzBypassScanner's missing_authorizer technique.

Scanning a whole domain plus its enumerated subdomains means most hosts are
ordinary public websites, not API resources. A bare "GET returns 200 without a
token" is the normal state of the public web, so on its own it must not be a
critical finding. This covers:

  - catch-all hosts (same success page for GET and for destructive verbs) are
    suppressed entirely;
  - a public HTML page with no corroboration is dropped, not reported;
  - an API-shaped (JSON/XML) response is still flagged critical;
  - an ambiguous response (neither clearly API nor clearly a web page) is kept
    but downgraded to low severity;
  - corroboration (an authenticated-baseline match, or a sibling method that is
    actually protected) keeps a finding critical even for an HTML body;
  - a genuinely wide-open API (distinct bodies per method) is NOT mistaken for
    a catch-all and is still reported;
  - the Content-Type header takes precedence over body shape.

All offline: a scripted fake HTTP engine is injected, so no network is used.
"""

import difflib
from dataclasses import dataclass, field

from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget


@dataclass
class _Resp:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class _FakeHttp:
    """Scripts responses as a function of (method, url, headers)."""

    def __init__(self, responder):
        self._responder = responder

    def request(self, method, url, headers=None, body=None):
        return self._responder(method, url, headers or {})

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()


def _scanner(responder, confirm_destructive=True):
    return AuthzBypassScanner(
        scope_manager=None,
        http_engine=_FakeHttp(responder),
        confirm_destructive=confirm_destructive,
    )


def _missing_authorizer(findings):
    return [f for f in findings if f.category == "authz-bypass-missing-authorizer"]


# ------------------------------------------------------------ catch-all hosts


def test_catch_all_host_is_fully_suppressed():
    """Every method (GET/HEAD/POST/PUT/DELETE/PATCH) returns the same 200 page:
    the host ignores the method entirely (SPA/CDN/parked catch-all), so there
    is no missing authorizer to report."""
    page = "<!doctype html><html><body>Welcome to Acme</body></html>"

    def responder(method, url, headers):
        return _Resp(200, page)

    target = AuthzBypassTarget(
        url="https://pvz.example.com/",
        probe_authorizer_fail_open=False,  # isolate missing_authorizer
    )
    findings = _scanner(responder).run(target)
    assert findings == []


def test_distinct_bodies_per_method_are_not_a_catch_all():
    """A genuinely wide-open API returns *different* bodies per method - that is
    a real finding, not a catch-all, and must still be reported."""

    bodies = {
        "GET": '[{"id":1},{"id":2},{"id":3}]',
        "HEAD": "",
        "POST": '{"created":true,"id":99,"token":"abcdef0123456789"}',
        "PUT": '{"updated":true,"id":99,"status":"ok"}',
        "DELETE": '{"deleted":true,"id":99}',
        "PATCH": '{"patched":true,"fields":["a","b","c"]}',
    }

    def responder(method, url, headers):
        return _Resp(200, bodies.get(method, ""), {"Content-Type": "application/json"})

    target = AuthzBypassTarget(
        url="https://api.example.com/orders",
        probe_authorizer_fail_open=False,
    )
    findings = _missing_authorizer(_scanner(responder).run(target))
    assert findings, "a wide-open JSON API must not be silenced as a catch-all"
    assert all(f.severity == "critical" for f in findings)


# -------------------------------------------------- public HTML page is dropped


def test_public_html_page_without_corroboration_is_dropped():
    """GET returns a public HTML page (200), destructive verbs 404. No auth
    baseline, no protected sibling -> this is the normal public web, not a
    missing authorizer, so nothing is reported."""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(200, "<!doctype html><html><body>blog home</body></html>")
        return _Resp(404, "not found")

    target = AuthzBypassTarget(
        url="https://blog.example.com/",
        probe_authorizer_fail_open=False,
    )
    assert _missing_authorizer(_scanner(responder).run(target)) == []


# -------------------------------------------------- API JSON page stays critical


def test_api_json_leak_stays_critical():
    """An unauthenticated 200 that returns JSON data is an API resource leaking
    without a token - still a critical missing authorizer."""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(
                200,
                '{"order_id":123,"customer":"secret","card":"4111111111111111"}',
                {"Content-Type": "application/json"},
            )
        return _Resp(404, "")

    target = AuthzBypassTarget(
        url="https://api.example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
    )
    findings = _missing_authorizer(_scanner(responder).run(target))
    assert findings
    ma = findings[0]
    assert ma.severity == "critical"
    assert ma.evidence["response_class"] == "api"
    assert ma.evidence["corroborated"] is True


# ------------------------------------------------ ambiguous response downgraded


def test_ambiguous_response_downgraded_to_low():
    """A 200 that is neither clearly an API (JSON/XML) nor clearly a web page
    (HTML), with no corroboration, is kept as a trace but at low severity."""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(200, "neither json nor html, just some text")
        return _Resp(404, "")

    target = AuthzBypassTarget(
        url="https://odd.example.com/x",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
    )
    findings = _missing_authorizer(_scanner(responder).run(target))
    assert findings
    ma = findings[0]
    assert ma.severity == "low"
    assert ma.confidence <= 0.25
    assert ma.evidence["response_class"] == "unknown"


# ------------------------- public page that rejects writes (real-world FP)


def test_public_html_page_that_rejects_writes_is_not_flagged():
    """The real careers.example.com pattern: GET=200 HTML (a public page) and
    every write verb rejected with 403. A server declining POST/PUT/DELETE is
    NOT an authorization control, so this must produce NEITHER a missing-
    authorizer NOR a method-inconsistency finding. (It used to false-positive
    as two criticals via a 'sibling method is protected' heuristic.)"""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(200, "<!doctype html><html><body>Careers</body></html>")
        return _Resp(403, "forbidden")

    target = AuthzBypassTarget(
        url="https://careers.example.com/",
        probe_authorizer_fail_open=False,
    )
    findings = _scanner(responder).run(target)
    assert [f for f in findings if f.category == "authz-bypass-missing-authorizer"] == []
    assert [f for f in findings if f.category == "authz-bypass-method-inconsistency"] == []


def test_unauthenticated_write_is_critical_regardless_of_body():
    """An accepted UNAUTHENTICATED write (POST=200) is a real finding even when
    its response is HTML, not API-shaped: a state-changing verb ran with no
    credential. Safe-method public-page suppression must never weaken this."""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(401, "unauthorized")
        return _Resp(200, "<html>created</html>")  # write accepted, HTML body

    target = AuthzBypassTarget(
        url="https://api.example.com/orders",
        destructive_methods=["POST"],
        probe_authorizer_fail_open=False,
    )
    findings = _missing_authorizer(_scanner(responder).run(target))
    assert any(
        f.severity == "critical" and f.evidence["method"] == "POST" for f in findings
    )


def test_html_content_type_header_overrides_jsonish_body():
    """The server declares text/html but the body happens to start with '{'.
    Content-Type wins: this is a web page, not an API - so an uncorroborated
    one is dropped, not reported."""

    def responder(method, url, headers):
        if method in ("GET", "HEAD"):
            return _Resp(200, "{not actually json}", {"Content-Type": "text/html"})
        return _Resp(404, "")

    target = AuthzBypassTarget(
        url="https://site.example.com/",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
    )
    assert _missing_authorizer(_scanner(responder).run(target)) == []
