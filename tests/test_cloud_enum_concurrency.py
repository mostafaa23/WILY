"""Phase: cloud-enum candidate probing is concurrent, not sequential
(``scan_all._run_cloud_enum``).

Previously each generated candidate name (up to hundreds by default) was
probed one at a time with a plain ``for`` + ``await`` loop - with a ~10s
per-request timeout, a full run could take tens of minutes for no safety
reason, since every candidate is an independent, read-only, per-host probe.
These tests prove (a) probes genuinely overlap in time (bounded concurrency,
not one-at-a-time), and (b) findings from concurrent probes - including more
than one positive hit at once - are still correctly aggregated into the
shared ``all_findings`` list (a regression test for the closure bug where
``all_findings += found`` inside the concurrent worker needs ``nonlocal`` to
actually mutate the caller's list instead of silently shadowing it).
"""

import asyncio
import time

import pytest

from wily.cli.commands import scan_all
from wily.scanners.base import Finding


def _finding(asset: str, provider: str = "aws", bucket: str | None = None) -> Finding:
    return Finding(
        asset=asset,
        category="cloud-storage-open",
        severity="high",
        confidence=0.9,
        evidence={"provider": provider, "bucket": bucket or asset},
        discovery_source="cloud_storage_enum",
    )


@pytest.mark.asyncio
async def test_candidates_are_probed_concurrently_not_one_at_a_time(monkeypatch):
    """A fake probe that sleeps briefly must show real overlap: if candidates
    ran sequentially, max concurrent in-flight would never exceed 1."""
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_run_scanner(_scanner, _target):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)
    monkeypatch.setattr(
        scan_all, "generate_candidates", lambda *a, **k: [f"c{i}" for i in range(20)]
    )

    all_findings: list = []
    scanned: set = set()
    start = time.monotonic()
    await scan_all._run_cloud_enum(
        all_findings=all_findings,
        scanned=scanned,
        s3_scan_targets={},
        root_domain="example.com",
        keywords=["acme"],
        wordlist_path=None,
        max_candidates=None,
        rate_limiter=None,
        allow_local=False,
    )
    elapsed = time.monotonic() - start

    # 20 candidates x 0.05s would take 1.0s run strictly sequentially; with
    # real concurrency it finishes in a small fraction of that.
    assert elapsed < 0.5, f"looks sequential: took {elapsed:.2f}s for 20 candidates"
    assert max_in_flight > 1, "no real concurrency observed (max_in_flight == 1)"


@pytest.mark.asyncio
async def test_concurrent_positive_hits_all_reach_all_findings(monkeypatch):
    """Multiple candidates hitting "at once" must all land in all_findings -
    the regression case for the all_findings += found closure bug."""

    async def fake_run_scanner(_scanner, target):
        await asyncio.sleep(0.01)  # force overlap with other in-flight probes
        if target.name in ("hit-a", "hit-b", "hit-c"):
            return [_finding(f"{target.name}.s3.amazonaws.com", bucket=target.name)]
        return []

    monkeypatch.setattr(scan_all, "run_scanner", fake_run_scanner)
    names = ["miss-1", "hit-a", "miss-2", "hit-b", "miss-3", "hit-c", "miss-4"]
    monkeypatch.setattr(scan_all, "generate_candidates", lambda *a, **k: names)

    all_findings: list = []
    scanned: set = set()
    await scan_all._run_cloud_enum(
        all_findings=all_findings,
        scanned=scanned,
        s3_scan_targets={},
        root_domain="example.com",
        keywords=["acme"],
        wordlist_path=None,
        max_candidates=None,
        rate_limiter=None,
        allow_local=False,
    )

    found_buckets = {f.evidence["bucket"] for f in all_findings}
    assert found_buckets == {"hit-a", "hit-b", "hit-c"}
    assert ("cloud_storage_enum", "hit-a") in scanned
    assert ("cloud_storage_enum", "hit-b") in scanned
    assert ("cloud_storage_enum", "hit-c") in scanned
