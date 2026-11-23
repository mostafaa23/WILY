"""Tests for the optional email-the-report notifier (wily.notify.email_report).

No network and no AWS SDK: a fake http_post callable is injected, so these
assert the packaging and the request event shape against the public
send-report endpoint, not real HTTP calls.
"""

import base64
import io
import json
import zipfile

import pytest

from wily.notify import (
    DEFAULT_REPORT_ENDPOINT,
    ReportNotificationError,
    package_reports,
    send_report_via_http,
)


def _fake_post(status=200, body=None):
    """Build an injectable http_post that records its calls."""
    calls: list[tuple] = []
    text = json.dumps(body if body is not None else {"status": "sent", "message_id": "m-1"})

    def http_post(url, json_body, timeout):
        calls.append((url, json_body, timeout))
        return status, text

    return http_post, calls


# --------------------------------------------------------------- package_reports


def test_package_single_file_is_read_as_is(tmp_path):
    f = tmp_path / "report.json"
    f.write_text('{"findings": []}', encoding="utf-8")
    name, content = package_reports(f)
    assert name == "report.json"
    assert content == b'{"findings": []}'


def test_package_directory_is_zipped(tmp_path):
    d = tmp_path / "reports"
    (d / "a.com").mkdir(parents=True)
    (d / "a.com" / "report.json").write_text("{}", encoding="utf-8")
    (d / "a.com" / "scan.log").write_text("log line", encoding="utf-8")

    name, content = package_reports(d)
    assert name == "wily-reports.zip"
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        names = set(zf.namelist())
    assert names == {"a.com/report.json", "a.com/scan.log"}


def test_package_missing_path_raises(tmp_path):
    with pytest.raises(ReportNotificationError):
        package_reports(tmp_path / "nope.json")


def test_package_empty_directory_raises(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    with pytest.raises(ReportNotificationError):
        package_reports(d)


# ------------------------------------------------------------ send_report_via_http


def test_send_posts_base64_event_to_default_endpoint(tmp_path):
    report = tmp_path / "report.json"
    report.write_bytes(b'{"findings": [1, 2, 3]}')
    http_post, calls = _fake_post()

    result = send_report_via_http(
        recipient="tester@example.com",
        report_path=report,
        subject="Wily scan report",
        http_post=http_post,
    )

    assert len(calls) == 1
    url, event, _timeout = calls[0]
    assert url == DEFAULT_REPORT_ENDPOINT
    assert event["recipient"] == "tester@example.com"
    assert event["subject"] == "Wily scan report"
    assert event["report"]["encoding"] == "base64"
    assert base64.b64decode(event["report"]["content"]) == b'{"findings": [1, 2, 3]}'
    assert result["endpoint"] == DEFAULT_REPORT_ENDPOINT
    assert result["bytes"] == len(b'{"findings": [1, 2, 3]}')
    assert result["message_id"] == "m-1"


def test_send_uses_explicit_endpoint_over_default(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    http_post, calls = _fake_post()

    result = send_report_via_http(
        recipient="a@b.com",
        report_path=report,
        endpoint="https://self-hosted.example.com/",
        http_post=http_post,
    )
    assert calls[0][0] == "https://self-hosted.example.com/"
    assert result["endpoint"] == "https://self-hosted.example.com/"


def test_send_falls_back_to_env_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("WILY_REPORT_ENDPOINT", "https://env-endpoint.example.com/")
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    http_post, calls = _fake_post()

    send_report_via_http(recipient="a@b.com", report_path=report, http_post=http_post)
    assert calls[0][0] == "https://env-endpoint.example.com/"


def test_send_requires_a_recipient(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    http_post, _ = _fake_post()
    with pytest.raises(ReportNotificationError, match="recipient"):
        send_report_via_http(recipient="", report_path=report, http_post=http_post)


def test_send_raises_on_http_error_status(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    http_post, _ = _fake_post(status=500, body={"error": "boom"})
    with pytest.raises(ReportNotificationError, match="HTTP 500"):
        send_report_via_http(recipient="a@b.com", report_path=report, http_post=http_post)


def test_send_raises_when_status_is_not_sent(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    http_post, _ = _fake_post(status=200, body={"status": "queued"})
    with pytest.raises(ReportNotificationError, match="did not confirm"):
        send_report_via_http(recipient="a@b.com", report_path=report, http_post=http_post)


def test_send_wraps_network_errors(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")

    def failing_post(url, body, timeout):
        raise ConnectionError("no route to host")

    with pytest.raises(ReportNotificationError, match="could not reach"):
        send_report_via_http(recipient="a@b.com", report_path=report, http_post=failing_post)
