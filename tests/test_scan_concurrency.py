"""Performance work: bounded concurrency + wall-clock budgets.

These tests prove, entirely offline (no network, injected fakes/monkeypatch),
the behaviour added to make a large multi-subdomain scan finish in a sane time
without weakening safety or detection:

  1. ``scanners.base.run_scanner`` offloads a *synchronous* scanner to a worker
     thread, so awaiting several of them lets their blocking work genuinely
     overlap instead of serializing on the event loop.
  2. ``scan_all._scan_endpoints`` scans a host's endpoints with bounded
     concurrency (overlap > 1, never more than the configured bound in flight)
     and still folds every endpoint's findings into the shared list.
  3. The per-target wall-clock budget (``deadline``) cleanly stops queueing new
     endpoints once it passes, keeping whatever was already found.
  4. ``scan_all.run_scans`` scans independent targets concurrently and honours
     the overall ``--max-duration`` budget by not starting new targets past it.
"""

import asyncio
import time
import types

import pytest

from wily.cli.commands import scan_all
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import ScopeManager
from wily.scanners.base import BaseScanner, Finding, run_scanner
from wily.scanners.http_engine import HttpEngine

# --------------------------------------------------------------------------- #
# 1. run_scanner offloads a sync scanner to a thread (real overlap)
# --------------------------------------------------------------------------- #


class _SleepyScanner(BaseScanner):
    """A synchronous scanner whose run() blocks (time.sleep), like the real
    scanners blocking on requests I/O."""

    def __init__(self, delay: float) -> None:
        self.delay = delay

    def run(self, target):
        time.sleep(self.delay)
        return [
            Finding(
                asset=str(target),
                category="t",
                severity="low",
                confidence=0.1,
                evidence={},
                discovery_source="scanner",
            )
        ]


class _AsyncScanner(BaseScanner):
    async def run(self, target):
        await asyncio.sleep(0)
        return []


@pytest.mark.asyncio
async def test_run_scanner_offloads_sync_scanner_so_blocking_calls_overlap():
    delay = 0.2
    start = time.monotonic()
    # Three blocking scanners awaited "together": if run_scanner ran them inline
    # on the event loop, this would take ~3*delay; offloaded to threads it is
    # close to a single delay.
    results = await asyncio.gather(
        run_scanner(_SleepyScanner(delay), "a"),
        run_scanner(_SleepyScanner(delay), "b"),
        run_scanner(_SleepyScanner(delay), "c"),
    )
    elapsed = time.monotonic() - start
    assert all(len(r) == 1 for r in results)
    assert elapsed < delay * 2, (
        f"sync scanners did not overlap (took {elapsed:.2f}s for 3x{delay}s) - "
        "run_scanner is blocking the event loop"
    )


@pytest.mark.asyncio
async def test_run_scanner_still_awaits_async_scanner_directly():
    assert await run_scanner(_AsyncScanner(), "x") == []


# --------------------------------------------------------------------------- #
# Shared helpers for the endpoint-loop tests
# --------------------------------------------------------------------------- #


def _engine():
    scope = ScopeManager("example.com")
    return scope, HttpEngine(scope_manager=scope, rate_limiter=AdaptiveRateLimiter())


def _patch_param_discovery(monkeypatch):
    """Neutralise the per-endpoint parameter-discovery stage so these tests
    never touch the network: no params, no SSRF candidates."""
    monkeypatch.setattr(
        scan_all,
        "discover_parameters",
        lambda *a, **k: types.SimpleNamespace(probe_errors=0, probes_sent=0),
    )
    monkeypatch.setattr(scan_all, "select_ssrf_candidates", lambda *a, **k: [])


# --------------------------------------------------------------------------- #
# 2. _scan_endpoints: bounded concurrency + full aggregation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_scan_endpoints_runs_endpoints_concurrently_but_bounded(monkeypatch):
    _patch_param_discovery(monkeypatch)

    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_run_scanner(_scanner, _target):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.03)
        async with lock:
            in_flight -= 1
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)

    scope, engine = _engine()
    endpoints = [f"https://example.com/e{i}" for i in range(20)]
    all_findings: list = []
    bound = 5

    start = time.monotonic()
    skipped = await scan_all._scan_endpoints(
        endpoints=endpoints,
        all_findings=all_findings,
        scanned=set(),
        scope=scope,
        http_engine=engine,
        canary=None,
        token=None,
        yaml_rules=[],
        confirm_destructive=True,
        confirm_owned_infra=True,
        endpoint_concurrency=bound,
        deadline=None,
    )
    elapsed = time.monotonic() - start

    assert skipped == 0
    # Real overlap...
    assert max_in_flight > 1, "no concurrency observed across endpoints"
    # ...but never more than the configured bound in flight at once.
    assert max_in_flight <= bound, f"exceeded the concurrency bound: {max_in_flight} > {bound}"
    # 20 endpoints x (authz+cors) x 0.03s strictly sequential would be ~1.2s.
    assert elapsed < 0.8, f"looks sequential: {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_scan_endpoints_aggregates_all_endpoint_findings(monkeypatch):
    _patch_param_discovery(monkeypatch)

    async def fake_run_scanner(_scanner, target):
        await asyncio.sleep(0.005)  # force overlap
        return [
            Finding(
                asset=target.url,
                category="authz",
                severity="high",
                confidence=0.9,
                evidence={},
                discovery_source="scanner",
            )
        ]

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)

    scope, engine = _engine()
    endpoints = [f"https://example.com/e{i}" for i in range(10)]
    all_findings: list = []
    scanned: set = set()

    await scan_all._scan_endpoints(
        endpoints=endpoints,
        all_findings=all_findings,
        scanned=scanned,
        scope=scope,
        http_engine=engine,
        canary=None,
        token=None,
        yaml_rules=[],
        confirm_destructive=True,
        confirm_owned_infra=True,
        endpoint_concurrency=4,
        deadline=None,
    )

    # Every endpoint contributed its authz + cors findings to the shared list,
    # none lost to a concurrency race.
    assert len(all_findings) == len(endpoints) * 2
    assert {f.asset for f in all_findings} == set(endpoints)
    for ep in endpoints:
        assert ("authz_bypass", ep) in scanned
        assert ("cors_misconfig", ep) in scanned


# --------------------------------------------------------------------------- #
# 3. _scan_endpoints: per-target wall-clock budget (deadline)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_scan_endpoints_stops_at_deadline_and_keeps_partial(monkeypatch):
    _patch_param_discovery(monkeypatch)

    calls = {"n": 0}

    async def fake_run_scanner(_scanner, _target):
        calls["n"] += 1
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)

    scope, engine = _engine()
    endpoints = [f"https://example.com/e{i}" for i in range(8)]
    all_findings: list = []

    # A deadline already in the past: no endpoint should start its scanners.
    skipped = await scan_all._scan_endpoints(
        endpoints=endpoints,
        all_findings=all_findings,
        scanned=set(),
        scope=scope,
        http_engine=engine,
        canary=None,
        token=None,
        yaml_rules=[],
        confirm_destructive=True,
        confirm_owned_infra=True,
        endpoint_concurrency=4,
        deadline=time.monotonic() - 1.0,
    )

    assert skipped == len(endpoints)
    assert calls["n"] == 0, "scanners ran despite the budget being exhausted"
    assert all_findings == []


# --------------------------------------------------------------------------- #
# 4. run_scans: target-level concurrency + overall budget
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_scans_scans_targets_concurrently(monkeypatch, tmp_path):
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_run_full_scan(*, domain, output, **kwargs):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        from pathlib import Path

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text("{}", encoding="utf-8")
        return []

    monkeypatch.setattr(scan_all, "run_full_scan", fake_run_full_scan)

    await scan_all.run_scans(
        targets=["a.com", "b.com", "c.com", "d.com"],
        output="wily-report.json",
        output_dir=str(tmp_path / "out"),
        enum_subdomains=False,
        concurrency=3,
    )
    assert max_in_flight > 1, "targets did not scan concurrently"
    assert max_in_flight <= 3, f"exceeded target concurrency bound: {max_in_flight}"


@pytest.mark.asyncio
async def test_run_scans_concurrency_one_is_sequential(monkeypatch, tmp_path):
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_run_full_scan(*, domain, output, **kwargs):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        async with lock:
            in_flight -= 1
        from pathlib import Path

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text("{}", encoding="utf-8")
        return []

    monkeypatch.setattr(scan_all, "run_full_scan", fake_run_full_scan)

    await scan_all.run_scans(
        targets=["a.com", "b.com", "c.com"],
        output="wily-report.json",
        output_dir=str(tmp_path / "out"),
        enum_subdomains=False,
        concurrency=1,
    )
    assert max_in_flight == 1, "concurrency=1 should scan strictly one host at a time"


@pytest.mark.asyncio
async def test_run_scans_honours_overall_max_duration(monkeypatch, tmp_path):
    scanned_domains: list = []

    async def fake_run_full_scan(*, domain, output, **kwargs):
        scanned_domains.append(domain)
        await asyncio.sleep(0.1)  # push elapsed time past the small budget
        from pathlib import Path

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text("{}", encoding="utf-8")
        return []

    monkeypatch.setattr(scan_all, "run_full_scan", fake_run_full_scan)

    results = await scan_all.run_scans(
        targets=["a.com", "b.com", "c.com"],
        output="wily-report.json",
        output_dir=str(tmp_path / "out"),
        enum_subdomains=False,
        concurrency=1,  # strictly sequential so the budget check is deterministic
        max_duration=0.05,
    )

    # The first target runs; by the time it finishes, elapsed (0.1s) > 0.05s,
    # so the remaining targets are not started - but every target is still
    # represented in the results (the skipped ones with no findings).
    assert scanned_domains == ["a.com"]
    assert set(results) == {"a.com", "b.com", "c.com"}
    assert results["b.com"] == []
    assert results["c.com"] == []
