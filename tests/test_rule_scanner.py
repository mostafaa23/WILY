"""scanners.rule_scanner: the generic YAML-rule runner.

Driven through a fake HTTP engine (offline) so the matcher logic, the
read-only/authorization safety gates, and secret redaction are all exercised
without a live target.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.scanners.rule_scanner import RuleScanner, RuleScanTarget
from wily.templates.loader import load_rules
from wily.templates.schema import Template


@dataclass
class _Resp:
    status_code: int
    headers: dict = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 1.0
    url: str = ""


class _FakeHttp:
    """Returns a queued response per call and records what was sent."""

    def __init__(self, response: _Resp):
        self.response = response
        self.calls: list[tuple] = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        return self.response


def _builtin(rule_id: str) -> Template:
    for t in load_rules():
        if t.id == rule_id:
            return t
    raise AssertionError(f"built-in rule {rule_id!r} not found")


def _scanner(rules, response, confirm_owned_infra=False) -> RuleScanner:
    return RuleScanner(
        rules=rules,
        scope_manager=None,
        http_engine=_FakeHttp(response),
        confirm_owned_infra=confirm_owned_infra,
    )


# --- CORS origin reflection -------------------------------------------------

def test_cors_rule_fires_on_reflected_origin_with_credentials():
    rule = _builtin("cors-origin-reflection")
    resp = _Resp(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://evil-wily-probe.invalid",
            "Access-Control-Allow-Credentials": "true",
        },
        text='{"data": "sensitive"}',
    )
    scanner = _scanner([rule], resp)
    findings = scanner.run(RuleScanTarget(url="https://api.example.com/x"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "authz-bypass-cors-origin-reflection"
    assert f.severity == "critical"
    assert f.discovery_source == "template-rule"
    assert f.evidence["rule_id"] == "cors-origin-reflection"
    # Carries the shared dedup technique so it collapses with the code twin.
    assert f.evidence["technique"] == "cors_origin_reflection"
    # The forged Origin we sent must be the one that came back reflected.
    _method, _url, headers, _body = scanner.http.calls[0]
    assert headers["Origin"] == "https://evil-wily-probe.invalid"


def test_cors_rule_silent_when_origin_not_reflected():
    rule = _builtin("cors-origin-reflection")
    resp = _Resp(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    findings = _scanner([rule], resp).run(RuleScanTarget(url="https://api.example.com/x"))
    assert findings == []


def test_cors_rule_silent_without_credentials():
    rule = _builtin("cors-origin-reflection")
    resp = _Resp(
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://evil-wily-probe.invalid"},
    )
    findings = _scanner([rule], resp).run(RuleScanTarget(url="https://api.example.com/x"))
    assert findings == []


# --- Secret exposure (regex over body) + redaction --------------------------

def test_secret_rule_fires_and_redacts_the_raw_key():
    rule = _builtin("secret-exposure-response-body")
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    resp = _Resp(status_code=200, text=f'{{"aws_key": "{raw_key}"}}')
    findings = _scanner([rule], resp).run(RuleScanTarget(url="https://api.example.com/x"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "secret-exposure-response-body"
    # The raw secret must never appear anywhere in the finding's evidence.
    assert raw_key not in repr(f.evidence)
    matcher_frag = f.evidence["matchers"][0]
    assert "[REDACTED]" in "".join(matcher_frag["matches"])


def test_secret_rule_silent_on_clean_body():
    rule = _builtin("secret-exposure-response-body")
    resp = _Resp(status_code=200, text='{"status": "ok", "items": [1, 2, 3]}')
    findings = _scanner([rule], resp).run(RuleScanTarget(url="https://api.example.com/x"))
    assert findings == []


# --- Safety gates -----------------------------------------------------------

_POST_RULE = {
    "id": "unsafe-post-rule",
    "info": {"name": "writes", "severity": "high", "category": "test"},
    "asset-type": "http-endpoint",
    "request": [{"method": "POST", "path": "{{BaseURL}}"}],
    "matchers": [{"type": "status", "status": [200]}],
}

_OWNED_INFRA_RULE = {
    "id": "owned-infra-rule",
    "info": {"name": "needs owned infra", "severity": "high", "category": "test"},
    "asset-type": "http-endpoint",
    "authorization": {"mode": "passive", "requires-owned-infra": True},
    "request": [{"method": "GET", "path": "{{BaseURL}}"}],
    "matchers": [{"type": "status", "status": [200]}],
}

_DESTRUCTIVE_RULE = {
    "id": "destructive-rule",
    "info": {"name": "destructive", "severity": "high", "category": "test"},
    "asset-type": "http-endpoint",
    "authorization": {"mode": "destructive"},
    "request": [{"method": "GET", "path": "{{BaseURL}}"}],
    "matchers": [{"type": "status", "status": [200]}],
}


def test_write_method_rule_is_skipped_read_only():
    rule = Template.model_validate(_POST_RULE)
    scanner = _scanner([rule], _Resp(200))
    findings = scanner.run(RuleScanTarget(url="https://api.example.com/x"))
    assert findings == []
    assert scanner.http.calls == []  # never sent a POST
    assert any("read-only" in s.reason for s in scanner.skipped)


def test_destructive_mode_rule_is_skipped():
    rule = Template.model_validate(_DESTRUCTIVE_RULE)
    scanner = _scanner([rule], _Resp(200))
    assert scanner.run(RuleScanTarget(url="https://api.example.com/x")) == []
    assert any("destructive" in s.reason for s in scanner.skipped)


def test_owned_infra_rule_gated_off_by_default():
    rule = Template.model_validate(_OWNED_INFRA_RULE)
    scanner = _scanner([rule], _Resp(200), confirm_owned_infra=False)
    assert scanner.run(RuleScanTarget(url="https://api.example.com/x")) == []
    assert any("owned_infra" in s.reason for s in scanner.skipped)


def test_owned_infra_rule_runs_when_confirmed():
    rule = Template.model_validate(_OWNED_INFRA_RULE)
    scanner = _scanner([rule], _Resp(200), confirm_owned_infra=True)
    findings = scanner.run(RuleScanTarget(url="https://api.example.com/x"))
    assert len(findings) == 1


def test_asset_type_mismatch_is_skipped():
    rule = _builtin("cors-origin-reflection")  # asset-type http-endpoint
    scanner = _scanner([rule], _Resp(200))
    findings = scanner.run(
        RuleScanTarget(url="https://api.example.com/x", asset_type="s3-bucket")
    )
    assert findings == []
    assert any("asset-type" in s.reason for s in scanner.skipped)


def test_dsl_and_unresolved_placeholder_rules_are_skipped_not_matched():
    """The IMDS rule needs an out-of-band callback the runner can't provide:
    it must be skipped with a recorded reason, never silently reported."""
    rule = _builtin("cloud-ssrf-imds-candidate")
    scanner = _scanner([rule], _Resp(200), confirm_owned_infra=True)
    # Give it the matching asset-type so only the dsl/placeholder gate remains.
    findings = scanner.run(
        RuleScanTarget(url="https://api.example.com/x", asset_type="http-endpoint-with-param")
    )
    assert findings == []
    assert any(s.rule_id == "cloud-ssrf-imds-candidate" for s in scanner.skipped)


def test_yaml_cors_finding_dedupes_with_code_scanner():
    """The YAML CORS finding and CorsMisconfigScanner's finding on the same
    asset must collapse to one in the deterministic dedup pass."""
    from wily.risk.rules_engine import apply_deterministic_rules
    from wily.scanners.authz_bypass import CorsMisconfigScanner, CorsMisconfigTarget

    url = "https://api.example.com/x"
    resp = _Resp(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://evil-wily-probe.invalid",
            "Access-Control-Allow-Credentials": "true",
        },
        text="{}",
    )
    code = CorsMisconfigScanner(
        scope_manager=None, http_engine=_FakeHttp(resp)
    ).run(CorsMisconfigTarget(url=url, probe_origin="https://evil-wily-probe.invalid"))
    yaml_f = _scanner([_builtin("cors-origin-reflection")], resp).run(
        RuleScanTarget(url=url)
    )
    assert len(code) == 1 and len(yaml_f) == 1
    merged = apply_deterministic_rules(code + yaml_f)
    assert len(merged) == 1, "YAML CORS finding did not dedupe with the code twin"
