"""Tests for the optional email-the-report notifier (wily.notify.email_report).

No boto3 and no network: a fake Lambda client is injected, so these assert the
packaging and the invoke event shape, not real AWS calls.
"""

import base64
import io
import json
import zipfile

import pytest

from wily.notify import (
    ReportNotificationError,
    package_reports,
    send_report_via_lambda,
)


class _FakeLambda:
    """Stand-in for a boto3 Lambda client."""

    def __init__(self, payload: bytes = b'{"status": "sent"}', function_error=None):
        self.calls: list[dict] = []
        self._payload = payload
        self._function_error = function_error

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return {"Payload": io.BytesIO(self._payload), "FunctionError": self._function_error}


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


# ------------------------------------------------------------ send_report_via_lambda


def test_send_builds_base64_event_and_invokes(tmp_path):
    report = tmp_path / "report.json"
    report.write_bytes(b'{"findings": [1, 2, 3]}')
    fake = _FakeLambda()

    result = send_report_via_lambda(
        recipient="tester@example.com",
        report_path=report,
        function_name="wily-send-report",
        subject="Wily scan report",
        client=fake,
    )

    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["FunctionName"] == "wily-send-report"
    event = json.loads(call["Payload"].decode("utf-8"))
    assert event["recipient"] == "tester@example.com"
    assert event["subject"] == "Wily scan report"
    assert event["report"]["encoding"] == "base64"
    # The attachment round-trips back to the original bytes.
    assert base64.b64decode(event["report"]["content"]) == b'{"findings": [1, 2, 3]}'
    assert result["function"] == "wily-send-report"
    assert result["bytes"] == len(b'{"findings": [1, 2, 3]}')


def test_send_requires_a_function_name(tmp_path, monkeypatch):
    monkeypatch.delenv("WILY_REPORT_LAMBDA", raising=False)
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ReportNotificationError, match="Lambda function"):
        send_report_via_lambda(
            recipient="a@b.com", report_path=report, client=_FakeLambda()
        )


def test_send_falls_back_to_env_function_name(tmp_path, monkeypatch):
    monkeypatch.setenv("WILY_REPORT_LAMBDA", "env-fn")
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    fake = _FakeLambda()
    result = send_report_via_lambda(
        recipient="a@b.com", report_path=report, client=fake
    )
    assert result["function"] == "env-fn"
    assert fake.calls[0]["FunctionName"] == "env-fn"


def test_send_requires_a_recipient(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ReportNotificationError, match="recipient"):
        send_report_via_lambda(
            recipient="", report_path=report, function_name="fn", client=_FakeLambda()
        )


def test_send_surfaces_lambda_function_error(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    fake = _FakeLambda(payload=b'{"errorMessage": "boom"}', function_error="Unhandled")
    with pytest.raises(ReportNotificationError, match="returned an error"):
        send_report_via_lambda(
            recipient="a@b.com", report_path=report, function_name="fn", client=fake
        )
