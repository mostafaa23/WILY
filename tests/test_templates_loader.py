"""templates.loader: load_rules / validate_rules.

Covers the three behaviours the loader promises: a valid rule loads, a
malformed-YAML file is *reported* (not raised), and a schema-invalid file is
reported - all in one pass, so one bad file never hides the rest.
"""

from __future__ import annotations

from pathlib import Path

from wily.templates.loader import (
    default_rules_dir,
    load_rules,
    validate_rules,
)
from wily.templates.schema import Template

_VALID_RULE = """
id: test-valid-rule
info:
  name: "A valid test rule"
  severity: high
  category: test-category
asset-type: http-endpoint
request:
  - method: GET
    path: "{{BaseURL}}"
matchers:
  - type: status
    status: [200]
"""

_MALFORMED_YAML = """
id: test-broken
info:
  name: "unterminated
  severity: high
request: [
"""

_SCHEMA_INVALID = """
id: test-schema-invalid
info:
  name: "missing severity and bad matcher"
  category: test
asset-type: http-endpoint
request:
  - method: GET
    path: "{{BaseURL}}"
matchers:
  - type: not-a-real-matcher-type
"""


def _write(dirpath: Path, name: str, content: str) -> Path:
    path = dirpath / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_valid_rule_loads(tmp_path: Path):
    _write(tmp_path, "ok/valid.yaml", _VALID_RULE)
    result = validate_rules(tmp_path)
    assert len(result["valid"]) == 1
    assert not result["invalid"]
    template = result["valid"][0]
    assert isinstance(template, Template)
    assert template.id == "test-valid-rule"
    assert template.asset_type == "http-endpoint"


def test_malformed_yaml_is_reported_not_raised(tmp_path: Path):
    _write(tmp_path, "bad/broken.yaml", _MALFORMED_YAML)
    result = validate_rules(tmp_path)  # must not raise
    assert result["valid"] == []
    assert len(result["invalid"]) == 1
    path, reason = result["invalid"][0]
    assert path.name == "broken.yaml"
    assert "yaml" in reason.lower()


def test_schema_invalid_is_reported(tmp_path: Path):
    _write(tmp_path, "bad/schema.yaml", _SCHEMA_INVALID)
    result = validate_rules(tmp_path)
    assert result["valid"] == []
    assert len(result["invalid"]) == 1
    _path, reason = result["invalid"][0]
    assert "validation" in reason.lower()


def test_empty_file_is_reported(tmp_path: Path):
    _write(tmp_path, "empty.yaml", "\n# just a comment\n")
    result = validate_rules(tmp_path)
    assert result["valid"] == []
    assert len(result["invalid"]) == 1


def test_one_bad_file_does_not_hide_the_good_ones(tmp_path: Path):
    _write(tmp_path, "a/valid.yaml", _VALID_RULE)
    _write(tmp_path, "b/broken.yaml", _MALFORMED_YAML)
    _write(tmp_path, "c/schema.yaml", _SCHEMA_INVALID)
    result = validate_rules(tmp_path)
    assert len(result["valid"]) == 1
    assert len(result["invalid"]) == 2


def test_load_rules_returns_only_valid_templates(tmp_path: Path):
    _write(tmp_path, "a/valid.yaml", _VALID_RULE)
    _write(tmp_path, "b/broken.yaml", _MALFORMED_YAML)
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    assert all(isinstance(r, Template) for r in rules)


def test_builtin_rules_all_valid():
    """Every rule shipped under templates/rules must load cleanly, or
    `wily templates validate` would report a broken built-in rule."""
    result = validate_rules(default_rules_dir())
    assert result["invalid"] == [], f"built-in rules failed: {result['invalid']}"
    assert len(result["valid"]) >= 3
    ids = {t.id for t in result["valid"]}
    assert "cors-origin-reflection" in ids
    assert "secret-exposure-response-body" in ids
    assert "cloud-ssrf-imds-candidate" in ids
