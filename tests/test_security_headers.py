"""Missing / weak HTTP security headers scanner (OWASP A02)."""

from dataclasses import dataclass

import pytest

from wily.cli.commands import scan_all
from wily.core.scope_manager import ScopeManager
from wily.scanners.http_engine import HttpEngine
from wily.scanners.security_headers import (
    CATEGORY,
    SecurityHeadersScanner,
    SecurityHeadersTarget,
    csp_weaknesses,
    evaluate_headers,
    severity_for,
)

HTML = {"Content-Type": "text/html; charset=utf-8"}

HARDENED = {
    **HTML,
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
}


# --- pure header evaluation --------------------------------------------------


def test_bare_html_https_response_reports_all_six_missing():
    a = evaluate_headers(dict(HTML), "https://example.com/")
    assert set(a.missing) == {
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Strict-Transport-Security",
    }
    assert severity_for(a) == "medium"


def test_hardened_response_is_clean():
    assert evaluate_headers(dict(HARDENED), "https://example.com/").empty


def test_header_lookup_is_case_insensitive():
    lowered = {k.lower(): v for k, v in HARDENED.items()}
    assert evaluate_headers(lowered, "https://example.com/").empty


def test_hsts_not_required_over_plain_http():
    a = evaluate_headers(dict(HTML), "http://example.com/")
    assert "Strict-Transport-Security" not in a.missing


def test_short_hsts_max_age_is_weak():
    h = {**HARDENED, "Strict-Transport-Security": "max-age=300"}
    a = evaluate_headers(h, "https://example.com/")
    assert "Strict-Transport-Security" in a.weak


def test_csp_frame_ancestors_satisfies_x_frame_options():
    h = {k: v for k, v in HARDENED.items() if k != "X-Frame-Options"}
    a = evaluate_headers(h, "https://example.com/")
    assert "X-Frame-Options" not in a.missing


def test_non_html_response_skips_document_only_headers():
    a = evaluate_headers({"Content-Type": "application/json"}, "https://api.example.com/")
    assert set(a.missing) == {"X-Content-Type-Options", "Strict-Transport-Security"}


@pytest.mark.parametrize(
    "policy, expected",
    [
        ("default-src 'self' 'unsafe-inline'", "default-src allows 'unsafe-inline'"),
        ("script-src 'self' 'unsafe-eval'", "script-src allows 'unsafe-eval'"),
        ("default-src *", "default-src allows any origin (*)"),
    ],
)
def test_weak_csp_sources_detected(policy, expected):
    assert expected in csp_weaknesses(policy)


def test_unsafe_inline_with_nonce_is_not_weak():
    assert csp_weaknesses("script-src 'self' 'unsafe-inline' 'nonce-abc123'") == []


def test_script_src_overrides_weak_default_src():
    # Scripts follow script-src; a permissive default-src no longer governs them.
    assert csp_weaknesses("default-src *; script-src 'self'") == []


def test_weak_csp_reported_in_assessment():
    h = {**HARDENED, "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"}
    a = evaluate_headers(h, "https://example.com/")
    assert "unsafe-inline" in a.weak["Content-Security-Policy"]
    assert "unsafe-eval" in a.weak["Content-Security-Policy"]
    assert severity_for(a) == "medium"


def test_report_only_csp_is_missing_and_weak():
    h = {k: v for k, v in HARDENED.items() if k != "Content-Security-Policy"}
    h["Content-Security-Policy-Report-Only"] = "default-src 'self'"
    a = evaluate_headers(h, "https://example.com/")
    assert "Content-Security-Policy" in a.missing
    assert "Report-Only" in a.weak["Content-Security-Policy"]


def test_versioned_banners_are_info_disclosure():
    h = {**HARDENED, "Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"}
    a = evaluate_headers(h, "https://example.com/")
    assert a.info_disclosure == {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.2",
    }
    assert not a.missing and not a.weak
    assert severity_for(a) == "low"


def test_versionless_server_banner_is_not_disclosure():
    a = evaluate_headers({**HARDENED, "Server": "cloudflare"}, "https://example.com/")
    assert a.info_disclosure == {}


def test_only_soft_headers_missing_is_low():
    h = {k: v for k, v in HARDENED.items() if k not in ("Referrer-Policy", "Permissions-Policy")}
    a = evaluate_headers(h, "https://example.com/")
    assert set(a.missing) == {"Referrer-Policy", "Permissions-Policy"}
    assert severity_for(a) == "low"


# --- scanner-level behaviour with a fake HTTP engine -------------------------


@dataclass
class _Resp:
    headers: dict
    text: str = ""
    status_code: int = 200
    url: str = ""


class _FakeHttp:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc
        self.calls: list[tuple[str, str, object]] = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        if self._exc:
            raise self._exc
        return self._resp


def test_scanner_emits_exactly_one_grouped_finding():
    headers = {**HTML, "Server": "nginx/1.18.0", "X-Powered-By": "Express"}
    http = _FakeHttp(_Resp(headers=headers, url="https://example.com/"))
    findings = SecurityHeadersScanner(http_engine=http).run(
        SecurityHeadersTarget(origin="https://example.com")
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY
    assert f.asset == "https://example.com"
    assert f.severity == "medium"
    assert len(f.evidence["missing"]) == 6
    assert f.evidence["info_disclosure"] == {"Server": "nginx/1.18.0"}
    assert set(f.evidence) >= {"missing", "weak", "info_disclosure"}
    assert "nosniff" in f.remediation and "max-age=31536000" in f.remediation
    # Read-only: exactly one GET, no body.
    assert http.calls == [("GET", "https://example.com", None)]


def test_scanner_clean_response_no_finding():
    http = _FakeHttp(_Resp(headers=dict(HARDENED), url="https://example.com/"))
    assert SecurityHeadersScanner(http_engine=http).run(
        SecurityHeadersTarget(origin="https://example.com")
    ) == []


def test_scanner_uses_final_url_scheme_after_redirect():
    # http:// origin redirected to https:// -> HSTS is now expected.
    http = _FakeHttp(_Resp(headers=dict(HTML), url="https://example.com/"))
    f = SecurityHeadersScanner(http_engine=http).run(
        SecurityHeadersTarget(origin="http://example.com")
    )[0]
    assert "Strict-Transport-Security" in f.evidence["missing"]


def test_scanner_request_error_returns_nothing():
    http = _FakeHttp(exc=RuntimeError("connection refused"))
    assert SecurityHeadersScanner(http_engine=http).run(
        SecurityHeadersTarget(origin="https://example.com")
    ) == []


def test_scanner_skips_5xx():
    http = _FakeHttp(_Resp(headers=dict(HTML), status_code=503, url="https://example.com/"))
    assert SecurityHeadersScanner(http_engine=http).run(
        SecurityHeadersTarget(origin="https://example.com")
    ) == []


# --- wiring: runs automatically per host, honouring the discovered port ------


async def _run_wiring(monkeypatch, endpoints, root, allow_local=False):
    captured: list[tuple[str, object]] = []

    async def fake_run_scanner(scanner, target):
        captured.append((getattr(scanner, "name", ""), target))
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)
    scope = ScopeManager(root, allow_local_targets=allow_local)
    await scan_all._run_cloud_scanners(
        all_findings=[],
        scanned=set(),
        s3_scan_targets={},
        endpoints=endpoints,
        imported=None,
        buckets=(),
        root_domain=root,
        scope=scope,
        http_engine=HttpEngine(scope_manager=scope),
        rate_limiter=None,
        allow_local=allow_local,
        confirm_s3_writes=False,
    )
    return [t for n, t in captured if n == "security_headers"]


@pytest.mark.asyncio
async def test_security_headers_runs_per_host_by_default(monkeypatch):
    targets = await _run_wiring(monkeypatch, [], "example.com")
    assert [t.origin for t in targets] == ["https://example.com"]


@pytest.mark.asyncio
async def test_security_headers_respects_discovered_port(monkeypatch):
    targets = await _run_wiring(monkeypatch, ["https://example.com:8443/api/v1"], "example.com")
    assert [t.origin for t in targets] == ["https://example.com:8443"]


@pytest.mark.asyncio
async def test_security_headers_runs_for_allow_local(monkeypatch):
    targets = await _run_wiring(monkeypatch, [], "localhost", allow_local=True)
    assert [t.origin for t in targets] == ["http://localhost"]
