"""Tests for the CI gate (wily scan --fail-on).

Covers the pure decision logic (thresholds, feedback exclusion, multi-domain)
and the CLI wiring (exit code 0/1, 'none' is a no-op) without running a scan.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from wily.cli.gate import (
    FailOn,
    count_over_threshold,
    evaluate_gate,
    format_gate_lines,
)
from wily.scanners.base import Finding

runner = CliRunner()


def _f(severity: str, evidence: dict | None = None) -> Finding:
    return Finding(
        asset="https://api.example.com/orders/1",
        category="authz-bypass-missing-authorizer",
        severity=severity,
        confidence=0.9,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
    )


# ---------------------------------------------------------------- thresholds


def test_none_never_counts():
    findings = [_f("critical"), _f("high"), _f("low")]
    assert count_over_threshold(findings, FailOn.none) == 0
    assert count_over_threshold(findings, "none") == 0


@pytest.mark.parametrize(
    "fail_on, expected",
    [
        ("low", 4),       # info excluded, low/medium/high/critical counted
        ("medium", 3),
        ("high", 2),
        ("critical", 1),
    ],
)
def test_threshold_counts_at_or_above(fail_on, expected):
    findings = [_f("info"), _f("low"), _f("medium"), _f("high"), _f("critical")]
    assert count_over_threshold(findings, fail_on) == expected


# ---------------------------------------------------------------- feedback


def test_feedback_false_positive_does_not_fail_the_build():
    findings = [
        _f("critical", {"feedback_verdict": "false_positive"}),
        _f("critical", {"feedback_verdict": "valid"}),
        _f("critical"),
    ]
    # Only the dismissed one is excluded; the other two still count.
    assert count_over_threshold(findings, "critical") == 2


# ---------------------------------------------------------------- multi-domain


def test_evaluate_gate_multi_domain_reports_each_failing_domain():
    results = {
        "a.com": [_f("high"), _f("low")],
        "b.com": [_f("low")],            # nothing at/above high
        "c.com": [_f("critical"), _f("high")],
    }
    gate = evaluate_gate(results, "high")
    assert gate.failed is True
    assert gate.total == 3
    assert gate.exit_code == 1
    assert set(gate.failing_domains) == {"a.com", "c.com"}
    assert gate.per_domain["b.com"] == 0


def test_evaluate_gate_passes_when_nothing_crosses():
    results = {"a.com": [_f("low"), _f("medium")]}
    gate = evaluate_gate(results, "high")
    assert gate.failed is False
    assert gate.exit_code == 0


def test_format_lines_none_is_silent():
    gate = evaluate_gate({"a.com": [_f("critical")]}, "none")
    assert format_gate_lines(gate) == []


def test_format_lines_passed_and_failed():
    passed = format_gate_lines(evaluate_gate({"a.com": [_f("low")]}, "high"))
    assert passed == ["GATE PASSED: no findings at or above high"]

    failed = format_gate_lines(
        evaluate_gate({"a.com": [_f("high")], "b.com": [_f("critical")]}, "high")
    )
    assert failed[-1] == "GATE FAILED: 2 finding(s) at or above high"
    # Multi-domain: each failing domain is named before the summary.
    assert any("a.com" in line for line in failed)
    assert any("b.com" in line for line in failed)


# ---------------------------------------------------------------- CLI wiring


def _patch_scan(monkeypatch, results):
    """Replace the whole scan with a stub returning canned findings, so the
    gate's exit-code wiring can be tested without touching the network."""
    async def fake_run_scans(**kwargs):
        return results

    from wily.cli import app as app_module

    monkeypatch.setattr(app_module.scan_all, "run_scans", fake_run_scans)
    return app_module.app


def test_cli_exits_1_when_gate_fails(monkeypatch):
    app = _patch_scan(monkeypatch, {"example.com": [_f("critical")]})
    result = runner.invoke(app, ["scan", "example.com", "--fail-on", "high"])
    assert result.exit_code == 1
    assert "GATE FAILED" in result.stdout


def test_cli_exits_0_when_gate_passes(monkeypatch):
    app = _patch_scan(monkeypatch, {"example.com": [_f("low")]})
    result = runner.invoke(app, ["scan", "example.com", "--fail-on", "high"])
    assert result.exit_code == 0
    assert "GATE PASSED" in result.stdout


def test_cli_default_none_never_fails(monkeypatch):
    app = _patch_scan(monkeypatch, {"example.com": [_f("critical")]})
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "GATE" not in result.stdout


def test_cli_rejects_invalid_fail_on_level(monkeypatch):
    app = _patch_scan(monkeypatch, {"example.com": [_f("critical")]})
    result = runner.invoke(app, ["scan", "example.com", "--fail-on", "bogus"])
    # Typer/Click rejects an invalid enum value with its usage exit code (2).
    assert result.exit_code == 2


def test_cli_scan_crash_exits_2_not_1(monkeypatch):
    """A crash in the scan itself must exit 2 (operational error), never 1 -
    otherwise a broken tool is indistinguishable from a gate hit in CI."""
    from wily.cli import app as app_module

    async def boom(**kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(app_module.scan_all, "run_scans", boom)
    result = runner.invoke(
        app_module.app, ["scan", "example.com", "--fail-on", "high"]
    )
    assert result.exit_code == 2
    assert "GATE FAILED" not in result.output
