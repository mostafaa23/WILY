"""The orchestrator's finding-driven follow-up executor (_run_followups) and
the broad-BOLA coverage helper (_bola_covered_assets).

Verifies the chaining the detection pass justifies is actually *run*, not just
recommended: a JWT/BOLA follow-up on a broken-authz endpoint and the deeper S3
write-permission step all execute, each recording itself so it never repeats;
ssrf_blind / iam_privesc are surfaced as recommendations without a run.

Fakes are injected for every scanner so no network or real identities are used.
"""

import asyncio
from dataclasses import dataclass
from typing import ClassVar

import wily.cli.commands.scan_all as scan_all
from wily.recon.api_discovery import DiscoveryReport
from wily.risk.triggers import FollowUp
from wily.scanners.base import Finding


def _finding(category, asset):
    return Finding(
        asset=asset, category=category, severity="critical", confidence=0.9,
        evidence={}, discovery_source="scanner",
    )


# --- _bola_covered_assets ----------------------------------------------------

def test_bola_covered_assets_returns_only_candidates():
    report = DiscoveryReport(target="https://x")
    report.add_endpoint("https://x/orders/1", source="disc", details={"bola_candidate": True})
    report.add_endpoint("https://x/public", source="disc", details={"bola_candidate": False})
    report.add_endpoint("https://x/no-details", source="disc")
    covered = scan_all._bola_covered_assets(report)
    assert covered == {"https://x/orders/1"}


# --- _run_followups ----------------------------------------------------------

class _FakeScanner:
    """Records its constructor kwargs on the class and returns one finding."""

    last_kwargs: ClassVar[dict] = {}

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs

    def run(self, target):
        return [_finding("deep-result", getattr(target, "url", getattr(target, "bucket", "?")))]


@dataclass
class _FakeBolaFinding:
    endpoint: str
    confidence: str = "HIGH"
    owner_identity: str = "a"
    tester_identity: str = "b"
    json_similarity: float = 0.99
    grounding: str = "replayed"
    notes: str = ""


class _FakeBolaTester:
    instances: ClassVar[list] = []

    def __init__(self, identities, **kwargs):
        self.identities = identities
        _FakeBolaTester.instances.append(self)

    async def run(self, report):
        # One finding per endpoint in the mini report.
        return [_FakeBolaFinding(endpoint=url) for url in report.endpoints]


def _run(followups, *, token=None, identities=None, s3_targets=None, scanned=None):
    findings: list = []
    scanned = scanned if scanned is not None else set()
    asyncio.run(
        scan_all._run_followups(
            followups=followups,
            all_findings=findings,
            scanned=scanned,
            scope=object(),
            http_engine=object(),
            token=token,
            identities=identities or [],
            s3_scan_targets=s3_targets or {},
        )
    )
    return findings, scanned


def test_jwt_followup_runs_and_records(monkeypatch):
    monkeypatch.setattr(scan_all, "JwtTamperScanner", _FakeScanner)
    fu = FollowUp("jwt_tamper", "https://x/orders", "broken authz -> deep JWT")
    findings, scanned = _run([fu], token="jwt.token.here")
    assert [f.category for f in findings] == ["deep-result"]
    assert ("jwt_tamper", "https://x/orders") in scanned


def test_jwt_followup_recommended_without_token(monkeypatch):
    monkeypatch.setattr(scan_all, "JwtTamperScanner", _FakeScanner)
    fu = FollowUp("jwt_tamper", "https://x/orders", "r")
    findings, scanned = _run([fu], token=None)  # no token -> cannot run
    assert findings == []
    assert ("jwt_tamper", "https://x/orders") not in scanned


def test_bola_followup_runs_per_asset(monkeypatch):
    _FakeBolaTester.instances = []
    monkeypatch.setattr(scan_all, "BolaTester", _FakeBolaTester)
    fu = FollowUp("bola", "https://x/orders", "broken authz -> cross-tenant")
    findings, scanned = _run([fu], identities=["id_a", "id_b"])
    assert [f.category for f in findings] == ["bola-cross-tenant-access"]
    assert findings[0].asset == "https://x/orders"
    assert ("bola", "https://x/orders") in scanned
    # The follow-up built a one-endpoint report flagged as a candidate.
    assert len(_FakeBolaTester.instances) == 1


def test_bola_followup_needs_two_identities(monkeypatch):
    monkeypatch.setattr(scan_all, "BolaTester", _FakeBolaTester)
    fu = FollowUp("bola", "https://x/orders", "r")
    findings, scanned = _run([fu], identities=["only_one"])
    assert findings == []
    assert ("bola", "https://x/orders") not in scanned


def test_s3_permcheck_reruns_with_confirm_writes(monkeypatch):
    monkeypatch.setattr(scan_all, "S3BucketScanner", _FakeScanner)

    @dataclass
    class _S3Target:
        bucket: str

    s3_targets = {"s3://victim": (object(), _S3Target(bucket="victim"))}
    fu = FollowUp("s3_permcheck", "s3://victim", "public -> check writable")
    findings, scanned = _run([fu], s3_targets=s3_targets)
    assert [f.category for f in findings] == ["deep-result"]
    assert _FakeScanner.last_kwargs.get("confirm_writes") is True
    assert ("s3_permcheck", "s3://victim") in scanned


def test_recommend_only_for_ssrf_and_iam(monkeypatch):
    # These have no safe standalone run path -> surfaced, never run, never scanned.
    fus = [
        FollowUp("ssrf_blind", "https://x/fetch", "confirm via OOB"),
        FollowUp("iam_privesc", "https://x/app.js", "leaked creds"),
    ]
    findings, scanned = _run(fus, token="t", identities=["a", "b"])
    assert findings == []
    assert scanned == set()


def test_already_scanned_pairs_are_skipped(monkeypatch):
    monkeypatch.setattr(scan_all, "JwtTamperScanner", _FakeScanner)
    fu = FollowUp("jwt_tamper", "https://x/orders", "r")
    findings, _scanned = _run(
        [fu], token="t", scanned={("jwt_tamper", "https://x/orders")}
    )
    assert findings == []  # deduped out before running
