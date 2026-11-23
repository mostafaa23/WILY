"""SARIF validity for GitHub Code Scanning upload.

GitHub's code-scanning upload (github/codeql-action/upload-sarif) needs a
2.1.0 log whose runs carry a named driver and whose every result has a
ruleId, a level, a message and a location. These tests lock that shape in,
plus the per-finding partialFingerprints that keep an alert stable across
runs for a black-box target that has no source file to anchor to.
"""

from __future__ import annotations

import json

from wily.report.sarif_report import export_sarif
from wily.scanners.base import Finding


def _finding(asset, category, severity, confidence=0.9, evidence=None):
    return Finding(
        asset=asset,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
    )


def _write(findings, tmp_path):
    path = export_sarif(findings, tmp_path / "out.sarif")
    return json.loads(path.read_text(encoding="utf-8"))


def test_driver_name_and_version_present(tmp_path):
    doc = _write([_finding("https://x/a", "authz-bypass", "critical")], tmp_path)
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Wily"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://")


def test_every_result_has_required_fields(tmp_path):
    findings = [
        _finding("https://api.example.com/orders/1", "authz-bypass-missing-authorizer", "critical"),
        _finding("s3://bucket", "s3-bucket-public", "high"),
        _finding("example.com", "takeover", "medium"),  # bare host -> wily:// uri
    ]
    doc = _write(findings, tmp_path)
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}

    for result in run["results"]:
        # GitHub requires each of these.
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"none", "note", "warning", "error"}
        assert result["message"]["text"]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc  # never empty
        # Stable fingerprint for alert tracking.
        assert "wily/finding/v1" in result["partialFingerprints"]


def test_severity_maps_to_level(tmp_path):
    doc = _write(
        [
            _finding("https://x/c", "authz-bypass", "critical"),
            _finding("https://x/m", "cors", "medium"),
            _finding("https://x/l", "info-leak", "low"),
        ],
        tmp_path,
    )
    by_rule = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert by_rule["authz-bypass"] == "error"
    assert by_rule["cors"] == "warning"
    assert by_rule["info-leak"] == "note"


def test_rule_carries_security_severity_for_github_buckets(tmp_path):
    doc = _write([_finding("https://x/a", "authz-bypass", "critical")], tmp_path)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"]


def test_fingerprint_is_stable_for_same_finding_shape(tmp_path):
    # Same category + endpoint shape, different concrete id -> same fingerprint,
    # so GitHub treats a re-scan as the same alert, not a new one.
    a = _write([_finding("https://api.x/orders/1", "bola", "high")], tmp_path)
    b = _write([_finding("https://api.x/orders/2", "bola", "high")], tmp_path)
    fp_a = a["runs"][0]["results"][0]["partialFingerprints"]["wily/finding/v1"]
    fp_b = b["runs"][0]["results"][0]["partialFingerprints"]["wily/finding/v1"]
    assert fp_a == fp_b
