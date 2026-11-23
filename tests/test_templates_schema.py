"""templates.schema: validate the shipped sample rules against the schema."""

from __future__ import annotations

import yaml

from wily.templates.loader import default_rules_dir
from wily.templates.schema import (
    AuthorizationMode,
    MatcherType,
    Severity,
    Template,
)


def _load_yaml(rule_id: str) -> dict:
    for path in sorted(default_rules_dir().rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("id") == rule_id:
            return data
    raise AssertionError(f"rule {rule_id!r} not found under built-in rules")


def test_sample_imds_rule_is_valid():
    template = Template.model_validate(_load_yaml("cloud-ssrf-imds-candidate"))
    assert template.id == "cloud-ssrf-imds-candidate"
    assert template.info.severity == Severity.HIGH
    # asset-type / requires-owned-infra aliases must populate.
    assert template.asset_type == "http-endpoint-with-param"
    assert template.authorization.requires_owned_infra is True
    assert template.authorization.mode == AuthorizationMode.PASSIVE


def test_cors_rule_schema_fields():
    template = Template.model_validate(_load_yaml("cors-origin-reflection"))
    assert template.info.severity == Severity.CRITICAL
    assert template.variables["probe_origin"] == "https://evil-wily-probe.invalid"
    # use_enum_values makes matcher.type a plain string equal to the enum value.
    assert template.matchers[0].type == MatcherType.WORD.value
    assert template.matchers_condition == "and"


def test_secret_rule_regex_matchers():
    template = Template.model_validate(_load_yaml("secret-exposure-response-body"))
    assert template.matchers[0].type == MatcherType.REGEX.value
    assert template.matchers[0].regex  # non-empty pattern list
