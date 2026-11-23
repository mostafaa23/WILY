"""The full scan wires a per-endpoint soft-404 baseline into the Auth Bypass
check, so catch-all / SPA routes that answer 200 to every path are no longer
reported as critical "missing authorizer" findings.

Covers the URL builder (``_soft_404_probe_url``) and its effect when its URL
is fed to AuthzBypassScanner against a scripted catch-all target.
"""

import difflib
from dataclasses import dataclass

from wily.cli.commands.scan_all import _soft_404_probe_url
from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget


def test_replaces_last_segment_with_marker():
    assert (
        _soft_404_probe_url("https://x.com/api/users/1", token="abc")
        == "https://x.com/api/users/wily-nx-abc"
    )


def test_trailing_slash_replaces_last_real_segment():
    assert (
        _soft_404_probe_url("https://x.com/api/users/", token="abc")
        == "https://x.com/api/wily-nx-abc"
    )


def test_root_and_empty_path():
    assert _soft_404_probe_url("https://x.com/", token="abc") == "https://x.com/wily-nx-abc"
    assert _soft_404_probe_url("https://x.com", token="abc") == "https://x.com/wily-nx-abc"


def test_query_and_fragment_dropped_port_kept():
    assert (
        _soft_404_probe_url("http://127.0.0.1:8080/a/b?id=1#frag", token="abc")
        == "http://127.0.0.1:8080/a/wily-nx-abc"
    )


def test_random_marker_differs_from_endpoint():
    url = "https://x.com/orders/1"
    probe = _soft_404_probe_url(url)
    assert probe != url
    assert probe.startswith("https://x.com/orders/wily-nx-")


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, responder):
        self._responder = responder

    def request(self, method, url, headers=None, body=None):
        return self._responder(method, url, headers or {})

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()


_SPA_SHELL = "<!doctype html><html><body><div id=root></div><script src=/app.js></script></body></html>"


def _run(responder, url):
    scanner = AuthzBypassScanner(scope_manager=None, http_engine=_FakeHttp(responder))
    target = AuthzBypassTarget(
        url=url,
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
        soft_404_probe_url=_soft_404_probe_url(url),
    )
    return scanner.run(target)


def test_spa_catch_all_is_not_reported():
    """Every path returns the same SPA shell -> no missing-authorizer finding."""
    assert _run(lambda m, u, h: _Resp(200, _SPA_SHELL), "https://x.com/admin/backup") == []


def test_real_unauthenticated_resource_still_reported():
    def responder(method, url, headers):
        if "wily-nx-" in url:
            return _Resp(404, '{"error":"not found"}')
        return _Resp(200, '{"invoice_id":7,"customer":"acme","total":1200,"iban":"DE89..."}')

    findings = _run(responder, "https://x.com/invoices/7")
    assert {f.category for f in findings} == {"authz-bypass-missing-authorizer"}
