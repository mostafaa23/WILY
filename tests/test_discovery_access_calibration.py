"""Negative-response calibration in the discovery pipeline
(``recon/api_discovery.py``).

Proves the wildcard / auto-calibration behavior that stops Wily from (a)
reporting an SSO/login gate as thousands of fake endpoints and (b) sweeping a
full wordlist against a dead or auth-walled host. Offline: ``_probe`` is
replaced with a scripted fake, so no real HTTP happens.

Real-world driver: scanning ``el-data-science.abb.com`` (302-redirects every
path to login.windows.net) reported 7933 fake endpoints; ``ee.inside.abb.com``
(unreachable) swept 7933 routes to find nothing.
"""

from urllib.parse import urlparse

import pytest

from wily.core.scope_manager import ScopeManager
from wily.recon.api_discovery import (
    ACCESS_AUTH_WALL,
    ACCESS_CATCH_ALL,
    ACCESS_DEAD,
    ACCESS_OPEN,
    ApiDiscoveryPipeline,
    DiscoveryConfig,
    DiscoveryReport,
    _capped_errors,
    _Probe,
)

HOST = "el-data-science.abb.com"
TARGET = f"https://{HOST}"


def _pipeline(probe_fn):
    """Build a pipeline whose ``_probe`` is the scripted ``probe_fn(url)`` and
    which records every probed URL on ``p.calls``."""
    cfg = DiscoveryConfig(
        target=TARGET, scope=ScopeManager(HOST), aggressive=True, deep_fuzz=False
    )
    p = ApiDiscoveryPipeline(cfg)
    p.calls = []

    async def _fake_probe(url):
        p.calls.append(url)
        return probe_fn(url)

    p._probe = _fake_probe
    return p


def _redirect(host):
    return _Probe(302, None, None, redirect_host=host)


# ------------------------------------------------------------- _calibrate_access


@pytest.mark.asyncio
async def test_calibrate_auth_wall_offscope_redirect():
    p = _pipeline(lambda url: _redirect("login.windows.net"))
    access = await p._calibrate_access()
    assert access["state"] == ACCESS_AUTH_WALL
    assert access["auth_host"] == "login.windows.net"
    assert "Microsoft Entra ID" in access["reason"]


@pytest.mark.asyncio
async def test_calibrate_auth_wall_401():
    p = _pipeline(lambda url: _Probe(401, 0, None))
    access = await p._calibrate_access()
    assert access["state"] == ACCESS_AUTH_WALL
    assert "401" in access["reason"]


@pytest.mark.asyncio
async def test_calibrate_dead_host():
    p = _pipeline(lambda url: None)
    access = await p._calibrate_access()
    assert access["state"] == ACCESS_DEAD


@pytest.mark.asyncio
async def test_calibrate_catch_all_soft_404():
    p = _pipeline(lambda url: _Probe(200, 500, "text/html"))
    access = await p._calibrate_access()
    assert access["state"] == ACCESS_CATCH_ALL
    assert access["soft_signature"] == (200, 500, "text/html")


@pytest.mark.asyncio
async def test_calibrate_open_genuine_404():
    p = _pipeline(lambda url: _Probe(404, 0, "text/html"))
    access = await p._calibrate_access()
    assert access["state"] == ACCESS_OPEN


@pytest.mark.asyncio
async def test_calibrate_in_scope_redirect_is_not_auth_wall():
    # A 3xx that stays on the target host is a real redirect, not a login gate.
    p = _pipeline(lambda url: _redirect(HOST))
    access = await p._calibrate_access()
    assert access["state"] != ACCESS_AUTH_WALL


# --------------------------------------------------- _redirect_is_offscope helper


def test_redirect_is_offscope_classification():
    p = _pipeline(lambda url: None)
    assert p._redirect_is_offscope(_redirect("login.windows.net")) is True
    assert p._redirect_is_offscope(_redirect(HOST)) is False
    assert p._redirect_is_offscope(_Probe(200, 0, "text/html")) is False  # not a redirect
    assert p._redirect_is_offscope(_Probe(302, None, None, None)) is False  # no Location
    assert p._redirect_is_offscope(None) is False


# ------------------------------------------------- _stage_fuzz end-to-end behavior


@pytest.mark.asyncio
async def test_stage_fuzz_auth_wall_reports_zero_and_skips_sweep():
    p = _pipeline(lambda url: _redirect("login.windows.net"))
    report = DiscoveryReport(target=TARGET)
    await p._stage_fuzz(report)

    assert len(report.endpoints) == 0  # the 7933-fake-endpoints bug is gone
    assert report.stats["access"]["state"] == ACCESS_AUTH_WALL
    assert report.stats["access"]["auth_host"] == "login.windows.net"
    # Only the 3 calibration probes ran - the 56-route sweep was skipped.
    assert len(p.calls) == 3


@pytest.mark.asyncio
async def test_stage_fuzz_dead_host_skips_sweep():
    p = _pipeline(lambda url: None)
    report = DiscoveryReport(target=TARGET)
    await p._stage_fuzz(report)

    assert len(report.endpoints) == 0
    assert report.stats["access"]["state"] == ACCESS_DEAD
    assert len(p.calls) == 3


@pytest.mark.asyncio
async def test_stage_fuzz_open_keeps_real_endpoints_filters_offscope_redirects():
    def probe(url):
        path = urlparse(url).path
        if path.startswith("/wily-"):
            return _Probe(404, 0, "text/html")       # calibration -> open
        if path == "/api":
            return _Probe(200, 1234, "application/json")  # real endpoint -> keep
        if path == "/api/v1":
            return _redirect(HOST)                    # in-scope redirect -> keep
        if path == "/api/v2":
            return _redirect("login.windows.net")     # off-scope gate -> drop
        return _Probe(404, 0, "text/html")

    p = _pipeline(probe)
    report = DiscoveryReport(target=TARGET)
    await p._stage_fuzz(report)

    assert report.stats["access"]["state"] == ACCESS_OPEN
    paths = {urlparse(k).path for k in report.endpoints}
    assert "/api" in paths                 # real 200 kept
    assert "/api/v1" in paths              # in-scope redirect kept
    assert "/api/v2" not in paths          # off-scope auth redirect dropped
    assert len(p.calls) > 3               # the sweep actually ran


# ------------------------------------------------------------------ errors cap


def test_capped_errors_truncates_with_note():
    small = [f"e{i}" for i in range(10)]
    assert _capped_errors(small) == small  # unchanged under the cap

    big = [f"e{i}" for i in range(500)]
    out = _capped_errors(big)
    assert len(out) == 201                 # 200 kept + 1 truncation note
    assert "truncated" in out[-1]
