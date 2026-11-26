"""Tests for the php2shell / PHP-to-shell scanner (php_shell.py).

Covers the safe default-automatic detection (version banner + legacy-path
exposure), the patched-version negative case, the gated opt-in active
confirmation (raises ScannerConfirmationError without confirm_exploit), and
that the scanner is wired to run automatically per host in a normal scan.

A scripted fake HTTP engine is injected (the scanner accepts http_engine=),
so no real network is touched.
"""

from dataclasses import dataclass, field

import pytest

from wily.cli.commands import scan_all
from wily.core.scope_manager import ScopeManager
from wily.scanners.base import ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine
from wily.scanners.php_shell import (
    PhpShellScanner,
    PhpShellTarget,
    parse_php_version,
    php_version_status,
)


@dataclass
class _Resp:
    status_code: int
    headers: dict = field(default_factory=dict)
    text: str = ""


class _FakeHttp:
    """Scripts responses as a function of (method, url)."""

    def __init__(self, responder):
        self._responder = responder
        self.requests: list[tuple[str, str]] = []

    def request(self, method, url, headers=None, body=None):
        self.requests.append((method, url))
        return self._responder(method, url, headers or {}, body)


def _scanner(responder, confirm_exploit=False):
    return PhpShellScanner(
        scope_manager=None,
        http_engine=_FakeHttp(responder),
        confirm_exploit=confirm_exploit,
    )


# --- pure helpers -----------------------------------------------------------
def test_parse_php_version_three_and_two_part():
    assert parse_php_version("PHP/8.3.12") == (8, 3, 12)
    assert parse_php_version("Apache/2.4.58 (Unix) PHP/8.2.20") == (8, 2, 20)
    # Branch-only banner: patch reported as -1 (unknown patch level).
    assert parse_php_version("PHP/8.3") == (8, 3, -1)
    assert parse_php_version("nginx") is None


def test_php_version_status_classification():
    assert php_version_status((8, 3, 12))[0] == "vulnerable"  # < 8.3.36
    assert php_version_status((8, 3, 36))[0] == "patched"
    assert php_version_status((8, 2, 35))[0] == "patched"
    assert php_version_status((8, 1, 99))[0] == "vulnerable"  # EOL branch
    assert php_version_status((7, 4, 3))[0] == "vulnerable"  # EOL branch
    assert php_version_status((8, 9, 0))[0] == "unknown"  # future branch


# --- (a) vulnerable banner -> finding ---------------------------------------
def test_vulnerable_version_banner_flagged():
    def responder(method, url, headers, body):
        if url.endswith("eval-stdin.php"):
            return _Resp(404)
        return _Resp(200, headers={"X-Powered-By": "PHP/8.3.12"})

    findings = _scanner(responder).run(
        PhpShellTarget(url="https://victim.example")
    )
    version = [f for f in findings if f.category == "php2shell-cve-2026-109618-109619"]
    assert len(version) == 1
    f = version[0]
    assert f.severity == "critical"
    assert f.confidence == 0.6  # safe, version-only signal
    assert f.evidence["php_version"] == "8.3.12"
    assert f.evidence["patched_version"] == "8.3.36"
    assert f.evidence["active_upload_progress_confirmation"] is False


def test_version_banner_from_server_header():
    def responder(method, url, headers, body):
        if url.endswith("eval-stdin.php"):
            return _Resp(404)
        return _Resp(200, headers={"Server": "Apache/2.4.58 PHP/8.2.20"})

    findings = _scanner(responder).run(PhpShellTarget(url="https://victim.example"))
    f = next(f for f in findings if f.category == "php2shell-cve-2026-109618-109619")
    assert f.evidence["banner_source_header"] == "server"
    assert f.evidence["php_version"] == "8.2.20"


# --- (b) patched banner -> no finding ---------------------------------------
def test_patched_version_banner_not_flagged():
    def responder(method, url, headers, body):
        if url.endswith("eval-stdin.php"):
            return _Resp(404)
        return _Resp(200, headers={"X-Powered-By": "PHP/8.3.36"})

    findings = _scanner(responder).run(PhpShellTarget(url="https://ok.example"))
    assert [f for f in findings if "php2shell" in f.category] == []


def test_no_php_banner_no_version_finding():
    def responder(method, url, headers, body):
        if url.endswith("eval-stdin.php"):
            return _Resp(404)
        return _Resp(200, headers={"Server": "nginx"})

    findings = _scanner(responder).run(PhpShellTarget(url="https://quiet.example"))
    assert [f for f in findings if "php2shell" in f.category] == []


# --- legacy path exposure (CVE-2017-9841), safe GET presence ----------------
def test_phpunit_eval_stdin_exposure_flagged():
    def responder(method, url, headers, body):
        if url.endswith("eval-stdin.php"):
            return _Resp(200, text="")  # reachable
        return _Resp(200, headers={"Server": "nginx"})  # no PHP banner

    findings = _scanner(responder).run(PhpShellTarget(url="https://legacy.example"))
    legacy = [f for f in findings if f.category == "php-rce-cve-2017-9841"]
    assert len(legacy) == 1  # only one despite several path variants
    assert legacy[0].severity == "high"
    assert legacy[0].evidence["response_status"] == 200


def test_eval_stdin_probe_is_get_only_no_payload():
    """The legacy-path probe must be a GET with no body (harmless)."""
    fake = _FakeHttp(lambda m, u, h, b: _Resp(404))
    scanner = PhpShellScanner(scope_manager=None, http_engine=fake)
    scanner.run(PhpShellTarget(url="https://x.example"))
    eval_reqs = [(m, u) for (m, u) in fake.requests if u.endswith("eval-stdin.php")]
    assert eval_reqs, "legacy paths should have been probed"
    assert all(m == "GET" for m, _ in eval_reqs)


# --- (c) opt-in active confirmation is gated --------------------------------
def test_active_confirmation_requires_confirm_exploit():
    def responder(method, url, headers, body):
        return _Resp(200, headers={"X-Powered-By": "PHP/8.3.12"})

    target = PhpShellTarget(
        url="https://victim.example", attempt_active_confirmation=True
    )
    # Default scanner (confirm_exploit=False) must refuse the active path.
    with pytest.raises(ScannerConfirmationError):
        _scanner(responder).run(target)


def test_active_confirmation_raises_confidence_when_reachable():
    def responder(method, url, headers, body):
        if method == "POST":
            return _Resp(200)  # benign upload-progress request accepted
        if url.endswith("eval-stdin.php"):
            return _Resp(404)
        return _Resp(200, headers={"X-Powered-By": "PHP/8.3.12"})

    target = PhpShellTarget(
        url="https://victim.example", attempt_active_confirmation=True
    )
    findings = _scanner(responder, confirm_exploit=True).run(target)
    f = next(f for f in findings if f.category == "php2shell-cve-2026-109618-109619")
    assert f.confidence == 0.8  # corroborated
    assert f.evidence["active_upload_progress_confirmation"] is True


def test_automatic_scan_sends_no_post():
    """The default automatic path is non-destructive: GET/HEAD only, never a
    POST to the session.upload_progress handler."""
    fake = _FakeHttp(
        lambda m, u, h, b: _Resp(200, headers={"X-Powered-By": "PHP/8.3.12"})
    )
    scanner = PhpShellScanner(scope_manager=None, http_engine=fake)
    scanner.run(PhpShellTarget(url="https://victim.example"))
    assert all(m == "GET" for m, _ in fake.requests)


# --- (d) wiring: runs automatically per host --------------------------------
@pytest.mark.asyncio
async def test_php_shell_runs_per_host_by_default(monkeypatch):
    ran: list[tuple[str, object]] = []

    async def fake_run_scanner(scanner, target):
        ran.append((getattr(scanner, "name", ""), getattr(target, "url", None)))
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)
    scope = ScopeManager("example.com")
    await scan_all._run_cloud_scanners(
        all_findings=[],
        scanned=set(),
        s3_scan_targets={},
        endpoints=[],
        imported=None,
        buckets=(),
        root_domain="example.com",
        scope=scope,
        http_engine=HttpEngine(scope_manager=scope),
        rate_limiter=None,
        allow_local=False,
        confirm_s3_writes=False,
    )
    assert ("php_shell", "https://example.com") in ran
