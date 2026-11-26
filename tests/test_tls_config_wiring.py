"""The TLS/SSL configuration scanner runs automatically on every in-scope host
during a normal scan (a handshake is as safe as a GET and needs no input), and
is skipped for --allow-local targets.

``run_scanner`` is faked so the wiring is checked without opening a socket.
"""

import pytest

from wily.cli.commands import scan_all
from wily.core.scope_manager import ScopeManager
from wily.scanners.http_engine import HttpEngine


@pytest.mark.asyncio
async def test_tls_config_runs_per_host_by_default(monkeypatch):
    ran: list[tuple[str, object]] = []

    async def fake_run_scanner(scanner, target):
        ran.append((getattr(scanner, "name", ""), getattr(target, "host", None)))
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
    assert ("tls_config", "example.com") in ran


@pytest.mark.asyncio
async def test_tls_config_skipped_for_allow_local(monkeypatch):
    ran: list[tuple[str, object]] = []

    async def fake_run_scanner(scanner, target):
        ran.append((getattr(scanner, "name", ""), getattr(target, "host", None)))
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)
    scope = ScopeManager("localhost", allow_local_targets=True)
    await scan_all._run_cloud_scanners(
        all_findings=[],
        scanned=set(),
        s3_scan_targets={},
        endpoints=[],
        imported=None,
        buckets=(),
        root_domain="localhost",
        scope=scope,
        http_engine=HttpEngine(scope_manager=scope),
        rate_limiter=None,
        allow_local=True,
        confirm_s3_writes=False,
    )
    assert not any(name == "tls_config" for name, _ in ran)
