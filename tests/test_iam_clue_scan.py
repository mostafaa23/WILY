"""Phase 1: IAM / ARN clue extractor (scanners/iam_clue_scan.py) + its trigger.

Driven entirely through provided text sources (offline), plus one fake-HTTP
case for the fetch path. Asserts that clues are identifiers (never credential
*values*), that account ids are masked, and that an IAM clue only escalates to
iam_privesc when an --iam-file was supplied.
"""

from dataclasses import dataclass

from wily.report.json_report import export_json
from wily.risk.triggers import TriggerContext, derive_followups
from wily.scanners.base import Finding
from wily.scanners.iam_clue_scan import (
    IamClueScanner,
    IamClueSource,
    IamClueTarget,
    looks_like_iac,
)

_ACCOUNT = "123456789012"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/AdminDeployRole"
_JS_WITH_CLUES = f"""
(function(){{
  var cfg = {{
    roleArn: "{_ROLE_ARN}",
    bucket: "arn:aws:s3:::my-app-prod-assets/config.json",
    RoleName: "service-worker-role",
    accountId: "{_ACCOUNT}"
  }};
  sts.assumeRole(cfg.roleArn);
}})();
"""


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        return _Resp(200, self.body)


def _run(content, location=""):
    target = IamClueTarget(
        sources=[IamClueSource(label="app.js", content=content, location=location)]
    )
    return IamClueScanner().run(target)


def test_extracts_each_clue_kind():
    findings = _run(_JS_WITH_CLUES)
    kinds = {f.category for f in findings}
    assert "iam-clue-arn" in kinds
    assert "iam-clue-assume-role" in kinds
    assert "iam-clue-role-name" in kinds
    assert "iam-clue-account-id" in kinds


def test_iam_arn_is_low_other_arn_is_info():
    findings = _run(_JS_WITH_CLUES)
    arns = [f for f in findings if f.category == "iam-clue-arn"]
    by_service = {f.evidence["aws_service"]: f for f in arns}
    assert by_service["iam"].severity == "low"
    assert by_service["s3"].severity == "info"
    # The role name is parsed out of the IAM role ARN.
    assert by_service["iam"].evidence["resource_type"] == "role"
    assert by_service["iam"].evidence["resource_name"] == "AdminDeployRole"


def test_account_id_is_masked_everywhere():
    findings = _run(_JS_WITH_CLUES)
    # The full account id never appears in any finding's evidence, whether it
    # came from an ARN, the labelled account id, or the role-arn.
    for f in findings:
        assert _ACCOUNT not in repr(f.evidence)
    acct = next(f for f in findings if f.category == "iam-clue-account-id")
    assert acct.evidence["value"] == "1234******12"


def test_masked_account_survives_report_even_unredacted(tmp_path):
    findings = _run(_JS_WITH_CLUES)
    # Even with redaction OFF the raw account id is absent: the scanner never
    # stored it.
    path = export_json(findings, tmp_path / "r.json", redact=False)
    assert _ACCOUNT not in path.read_text(encoding="utf-8")


def test_clean_source_yields_nothing():
    assert _run("const x = 1; // plain config, no aws here") == []


def test_bare_12_digit_number_is_not_an_account_clue():
    # No "account" label -> a lone 12-digit number is not treated as a clue.
    findings = _run("var ts = 100000000000; var count = 123456789012;")
    assert findings == []


def test_duplicate_clue_across_sources_reported_once():
    s1 = IamClueSource(label="a.js", content=f'x="{_ROLE_ARN}"')
    s2 = IamClueSource(label="b.js", content=f'y="{_ROLE_ARN}"')
    findings = IamClueScanner().run(IamClueTarget(sources=[s1, s2]))
    arns = [f for f in findings if f.category == "iam-clue-arn"]
    assert len(arns) == 1


def test_fetch_urls_scanned_via_http_engine_read_only():
    http = _FakeHttp(_JS_WITH_CLUES)
    target = IamClueTarget(fetch_urls=["https://x/bundle.js"])
    findings = IamClueScanner(scope_manager=None, http_engine=http).run(target)
    assert any(f.category == "iam-clue-arn" for f in findings)
    assert http.calls and http.calls[0][0] == "GET"  # detection only reads


def test_iac_file_source_is_flagged():
    tf = 'resource "aws_iam_role" "r" { }\nrole_arn = "' + _ROLE_ARN + '"\n'
    findings = _run(tf, location="https://x/main.tf")
    assert findings
    assert all(f.evidence["source_is_iac"] is True for f in findings)


def test_looks_like_iac_matches_known_suffixes():
    assert looks_like_iac("https://x/infra/main.tf")
    assert looks_like_iac("/deploy/serverless.yml")
    assert looks_like_iac("https://x/cloudformation.json?v=2")
    assert looks_like_iac("policy.json")
    assert not looks_like_iac("https://x/app.js")
    assert not looks_like_iac("")


# --- trigger-layer wiring --------------------------------------------------


def _clue_finding(category="iam-clue-arn", asset="https://x/app.js"):
    return Finding(
        asset=asset,
        category=category,
        severity="info",
        confidence=0.9,
        evidence={"clue_kind": "arn"},
        discovery_source="scanner",
    )


def test_iam_clue_triggers_iam_privesc_only_with_iam_file():
    findings = [_clue_finding()]
    # No IAM file -> nothing to corroborate against.
    assert derive_followups(findings, TriggerContext()) == []
    out = derive_followups(findings, TriggerContext(has_iam_file=True))
    assert [fu.scanner for fu in out] == ["iam_privesc"]
    assert out[0].asset == "https://x/app.js"


def test_iam_clue_privesc_followup_deduped_with_credential_leak():
    # An ARN clue and a leaked-credential finding on the SAME asset collapse to
    # one iam_privesc follow-up.
    findings = [
        _clue_finding(category="iam-clue-role-name", asset="https://x/app.js"),
        Finding(
            asset="https://x/app.js",
            category="secret-exposure-aws-access-key-id",
            severity="critical",
            confidence=0.9,
            evidence={},
            discovery_source="scanner",
        ),
    ]
    out = derive_followups(findings, TriggerContext(has_iam_file=True))
    assert [fu.scanner for fu in out] == ["iam_privesc"]
