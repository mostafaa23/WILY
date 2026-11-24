"""Passive subdomain enumeration (``recon/subdomain_enum.py``) and its wiring
into the orchestrator.

All offline: ``enumerate_subdomains`` takes an injectable ``runner`` that stands
in for the real subfinder subprocess, so no binary and no network are needed.
"""

import subprocess

import pytest

from wily.cli.commands import scan_all
from wily.recon import subdomain_enum
from wily.recon.subdomain_enum import (
    SubdomainResult,
    enumerate_subdomains,
    find_subfinder,
    target_host,
)

HOST = "example.com"


def _runner(stdout):
    def run(cmd, timeout):
        return stdout

    return run


# --------------------------------------------------------------- target_host


def test_target_host_strips_scheme_port_and_path():
    assert target_host("https://api.example.com/v1/users?x=1") == "api.example.com"
    assert target_host("example.com:8443") == "example.com"
    assert target_host("EXAMPLE.com") == "example.com"
    assert target_host("") == ""


# ---------------------------------------------------------- enumerate_subdomains


def test_enumerate_parses_dedupes_sorts_and_scopes():
    # api.* is repeated (dropped), attacker.com is off-scope (dropped),
    # EXAMPLE.COM is the apex (kept, lowercased), the blank line is ignored.
    out = (
        "api.example.com\n"
        "dev.example.com\n"
        "api.example.com\n"
        "evil.attacker.com\n"
        "EXAMPLE.COM\n"
        "\n"
    )
    res = enumerate_subdomains(HOST, runner=_runner(out))
    assert res.tool_available is True
    assert res.error is None
    # sorted, lowercased, de-duplicated, only in-scope names
    assert res.subdomains == ["api.example.com", "dev.example.com", "example.com"]


def test_enumerate_respects_max_results():
    out = "\n".join(f"h{i}.example.com" for i in range(10))
    res = enumerate_subdomains(HOST, runner=_runner(out), max_results=3)
    assert len(res.subdomains) == 3
    assert res.subdomains == ["h0.example.com", "h1.example.com", "h2.example.com"]


def test_enumerate_url_target_uses_hostname():
    res = enumerate_subdomains(
        "https://example.com/app", runner=_runner("api.example.com")
    )
    assert res.root == "example.com"
    assert res.subdomains == ["api.example.com"]


def test_enumerate_timeout_is_captured_not_raised():
    def boom(cmd, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout)

    res = enumerate_subdomains(HOST, runner=boom, timeout=5)
    assert res.tool_available is True
    assert res.error is not None and "timed out" in res.error
    assert res.subdomains == []


def test_enumerate_tool_missing_returns_install_hint(monkeypatch):
    # No runner injected + subfinder not resolvable -> graceful "not available".
    monkeypatch.setattr(subdomain_enum.shutil, "which", lambda _name: None)
    res = enumerate_subdomains(HOST)
    assert res.tool_available is False
    assert res.error is not None and "subfinder" in res.error.lower()
    assert res.subdomains == []


def test_find_subfinder_prefers_explicit_existing_path(tmp_path, monkeypatch):
    fake = tmp_path / "subfinder"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    assert find_subfinder(str(fake)) == str(fake)
    # falls back to PATH lookup when the explicit name is not a real file
    monkeypatch.setattr(subdomain_enum.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert find_subfinder("subfinder") == "/usr/bin/subfinder"


# ---------------------------------------------- _enumerate_and_merge (orchestrator)


def test_enumerate_and_merge_writes_file_and_dedupes(tmp_path, monkeypatch):
    def fake_enum(target, *, max_results=None, binary=None):
        if target == "example.com":
            return SubdomainResult(
                root="example.com",
                subdomains=["api.example.com", "dev.example.com"],
            )
        return SubdomainResult(root=target, subdomains=[])

    monkeypatch.setattr(scan_all, "enumerate_subdomains", fake_enum)

    merged = scan_all._enumerate_and_merge(
        ["example.com", "api.example.com"],   # api.* also returned by enum -> no dup
        output_dir=str(tmp_path),
        output="wily-report.json",
        max_results=None,
        binary=None,
    )

    assert merged == ["example.com", "api.example.com", "dev.example.com"]
    saved = (tmp_path / "subdomains.txt").read_text(encoding="utf-8").split()
    assert saved == ["example.com", "api.example.com", "dev.example.com"]


def test_enumerate_and_merge_survives_missing_tool(tmp_path, monkeypatch):
    def fake_enum(target, *, max_results=None, binary=None):
        return SubdomainResult(
            root=target, subdomains=[], tool_available=False, error="no subfinder"
        )

    monkeypatch.setattr(scan_all, "enumerate_subdomains", fake_enum)
    merged = scan_all._enumerate_and_merge(
        ["example.com"],
        output_dir=str(tmp_path),
        output="wily-report.json",
        max_results=None,
        binary=None,
    )
    # the root is still scanned even when enumeration could not run
    assert merged == ["example.com"]
    assert (tmp_path / "subdomains.txt").exists()


@pytest.mark.asyncio
async def test_run_scans_triggers_enumeration(tmp_path, monkeypatch):
    calls = {}

    def fake_merge(targets, *, output_dir, output, max_results, binary):
        calls["targets"] = targets
        return ["example.com", "api.example.com"]

    async def fake_full_scan(domain, output, **kwargs):
        return []

    monkeypatch.setattr(scan_all, "_enumerate_and_merge", fake_merge)
    monkeypatch.setattr(scan_all, "run_full_scan", fake_full_scan)
    monkeypatch.setattr(scan_all, "_print_scan_summary", lambda *a, **k: None)

    results = await scan_all.run_scans(
        targets=["example.com"],
        output="wily-report.json",
        output_dir=str(tmp_path),
        enum_subdomains=True,
        subdomain_max=50,
    )
    assert calls["targets"] == ["example.com"]
    # both the root and the discovered subdomain got scanned
    assert set(results) == {"example.com", "api.example.com"}
