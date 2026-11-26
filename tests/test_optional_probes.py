"""The four opt-in, single-URL scanners (session fixation, timing enumeration,
token entropy, stage inconsistency) are reachable via ``OptionalProbes``: each
runs once when its input is given, and nothing runs when none is configured.
A run-level test confirms the probe findings are injected into the first report.

``run_scanner`` is faked so no socket opens; the scanners' own behaviour is
covered by their dedicated test modules.
"""

import pytest

from wily.cli.commands import scan_all
from wily.cli.commands.scan_all import OptionalProbes


def _record(ran):
    async def fake_run_scanner(scanner, target):
        ran.append(getattr(scanner, "name", ""))
        return []

    return fake_run_scanner


def test_any_enabled():
    assert OptionalProbes().any_enabled() is False
    assert OptionalProbes(timing_url="https://x/auth").any_enabled() is True
    assert OptionalProbes(stage_template="https://{stage}.x/y").any_enabled() is True


@pytest.mark.asyncio
async def test_nothing_runs_when_no_probe_configured(monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr(scan_all, "run_scanner", _record(ran))
    found = await scan_all._run_optional_probes(OptionalProbes(), allow_local=False)
    assert found == []
    assert ran == []


@pytest.mark.asyncio
async def test_all_four_probes_run_when_configured(monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr(scan_all, "run_scanner", _record(ran))
    probes = OptionalProbes(
        session_fixation_login="https://example.com/login",
        session_fixation_body="username=a&password=b",
        timing_url="https://example.com/auth",
        timing_invalid_users=("nouser-xyz",),
        timing_candidate_users=("admin",),
        token_entropy_url="https://example.com/session",
        token_entropy_cookie="SESSIONID",
        stage_template="https://{stage}.api.example.com/private",
    )
    await scan_all._run_optional_probes(probes, allow_local=False)
    assert set(ran) == {
        "session_fixation",
        "timing_enum",
        "token_entropy",
        "stage_inconsistency",
    }


@pytest.mark.asyncio
async def test_only_the_configured_probe_runs(monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr(scan_all, "run_scanner", _record(ran))
    await scan_all._run_optional_probes(
        OptionalProbes(stage_template="https://{stage}.api.example.com/x"),
        allow_local=False,
    )
    assert ran == ["stage_inconsistency"]


@pytest.mark.asyncio
async def test_one_bad_probe_does_not_abort_the_others(monkeypatch):
    ran: list[str] = []

    async def flaky(scanner, target):
        name = getattr(scanner, "name", "")
        ran.append(name)
        if name == "timing_enum":
            raise RuntimeError("boom")
        return []

    monkeypatch.setattr(scan_all, "run_scanner", flaky)
    probes = OptionalProbes(
        timing_url="https://example.com/auth",
        token_entropy_url="https://example.com/session",
        token_entropy_cookie="SID",
    )
    # timing raises, but token_entropy still runs.
    await scan_all._run_optional_probes(probes, allow_local=False)
    assert "token_entropy" in ran


@pytest.mark.asyncio
async def test_run_scans_injects_probe_findings_into_first_report(monkeypatch, tmp_path):
    captured: dict = {}

    async def fake_probes(probes, *, allow_local):
        return ["PROBE_FINDING"]

    async def fake_full_scan(domain, output, **kwargs):
        captured[domain] = kwargs.get("extra_findings")
        return []

    monkeypatch.setattr(scan_all, "_run_optional_probes", fake_probes)
    monkeypatch.setattr(scan_all, "run_full_scan", fake_full_scan)

    await scan_all.run_scans(
        targets=["example.com"],
        output=str(tmp_path / "r.json"),
        optional_probes=OptionalProbes(stage_template="https://{stage}.api.example.com/x"),
    )
    assert captured["example.com"] == ["PROBE_FINDING"]
