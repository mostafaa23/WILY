"""Discovery now surfaces off-endpoint assets the target references - AWS S3
bucket URLs and the target's own JS bundles - so the S3 and secret / IAM-clue
scanners run automatically on a plain ``wily scan <domain>`` instead of only
with ``--scope-bucket`` or a traffic import.

All offline: the S3 regex and ``_mine_text`` are pure, and ``_stage_js`` is
exercised with a scripted ``_fetch_text`` (no network).
"""

import pytest

from wily.core.scope_manager import ScopeManager, extract_bucket_name
from wily.recon.api_discovery import (
    S3_REFERENCE_RE,
    ApiDiscoveryPipeline,
    DiscoveryConfig,
    DiscoveryReport,
)

HOST = "example.com"
TARGET = f"https://{HOST}"


def _pipeline():
    return ApiDiscoveryPipeline(DiscoveryConfig(target=TARGET, scope=ScopeManager(HOST)))


# -------------------------------------------------------------- the S3 regex


def test_s3_reference_regex_matches_the_three_forms_only():
    blob = (
        'a="https://assets-prod.s3.amazonaws.com/app/config.json";'
        'b="https://s3.eu-west-1.amazonaws.com/logs-bucket/key.txt";'
        "c='s3://backups-123/db.sql';"
        # NOT object storage - a non-S3 amazonaws host must be ignored:
        'd="https://api-xyz.execute-api.us-east-1.amazonaws.com/prod/orders";'
    )
    found = set(S3_REFERENCE_RE.findall(blob))
    # every match is parseable by the scanner's own bucket extractor
    buckets = {extract_bucket_name(r) for r in found}
    assert buckets == {"assets-prod", "logs-bucket", "backups-123"}
    assert not any("execute-api" in r for r in found)


# -------------------------------------------------------------- serialization


def test_to_json_includes_cloud_and_js_assets():
    r = DiscoveryReport(target=TARGET)
    r.cloud_assets.add("s3://b1/x")
    r.js_assets.add(f"{TARGET}/app.js")
    payload = r.to_json()
    assert payload["cloud_assets"] == ["s3://b1/x"]
    assert payload["js_assets"] == [f"{TARGET}/app.js"]


# ------------------------------------------------------------ _mine_text (pure)


def test_mine_text_collects_s3_refs_without_making_them_endpoints():
    p = _pipeline()
    report = DiscoveryReport(target=TARGET)
    text = 'fetch("/api/users"); var u="https://data-bkt.s3.amazonaws.com/f.json";'
    p._mine_text(text, TARGET, report, lambda raw, base: None, scan_chunks=False)

    # the bucket URL is collected as a cloud asset ...
    assert "https://data-bkt.s3.amazonaws.com/f.json" in report.cloud_assets
    # ... but an off-site bucket host is never recorded as an HTTP endpoint ...
    assert not any("amazonaws" in u for u in report.endpoints)
    # ... while the real same-site API path still becomes an endpoint.
    assert any(u.endswith("/api/users") for u in report.endpoints)


def test_mine_text_ignores_non_s3_amazonaws_hosts():
    p = _pipeline()
    report = DiscoveryReport(target=TARGET)
    text = 'x="https://abc.execute-api.us-east-1.amazonaws.com/prod/orders";'
    p._mine_text(text, TARGET, report, lambda raw, base: None, scan_chunks=False)
    assert report.cloud_assets == set()


# ------------------------------------------------------- _stage_js (end to end)


@pytest.mark.asyncio
async def test_stage_js_records_js_bundle_urls_and_their_s3_refs():
    p = _pipeline()
    report = DiscoveryReport(target=TARGET)

    homepage = '<html><head><script src="/static/app.js"></script></head></html>'
    bundle = 'fetch("/api/v1/me"); var b="https://leak-bkt.s3.amazonaws.com/secret.json";'

    async def fake_fetch(url):
        if url.rstrip("/") == TARGET:
            return homepage
        if url.endswith("/static/app.js"):
            return bundle
        return None

    p._fetch_text = fake_fetch
    await p._stage_js(report)

    # the JS bundle URL itself is kept (for secret/IAM scanning) ...
    assert any(u.endswith("/static/app.js") for u in report.js_assets)
    # ... and the S3 reference hidden inside the bundle was collected too.
    assert any("leak-bkt.s3.amazonaws.com" in c for c in report.cloud_assets)
