"""Phase 5 Lambda handler tests (offline, mocked client - no real SES/S3/network).

Loads lambda/send_report/handler.py by path ('lambda' is a Python keyword, so
it can't be imported as a normal module). Verifies env-var/event-driven config,
redaction-agnostic attachment building, S3 + inline + direct-invoke shapes, and
that NO address is hardcoded.
"""

import base64
import importlib.util
import json
from email import message_from_string
from pathlib import Path

import pytest

_HANDLER_PATH = (
    Path(__file__).resolve().parents[1] / "lambda" / "send_report" / "handler.py"
)

# The ``lambda/`` deployment code is intentionally kept out of the published
# repository (see .gitignore), so it is absent on a fresh clone / in CI. These
# tests exercise that handler directly, so skip the whole module when it is not
# present instead of erroring on the missing file.
pytestmark = pytest.mark.skipif(
    not _HANDLER_PATH.exists(),
    reason="lambda/send_report/handler.py is not part of this checkout",
)


def _load_handler():
    spec = importlib.util.spec_from_file_location("wily_send_report_handler", _HANDLER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeSes:
    def __init__(self):
        self.calls = []

    def send_raw_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "fake-message-id"}


class _FakeS3:
    def __init__(self, body=b"", metadata=None):
        self._body = body
        self._metadata = metadata or {}

    def get_object(self, Bucket, Key):
        class _Body:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        return {"Body": _Body(self._body), "Metadata": self._metadata}


@pytest.fixture
def handler_mod(monkeypatch):
    mod = _load_handler()
    fake_ses = _FakeSes()

    def _fake_client(service, region=None):
        if service == "ses":
            return fake_ses
        raise AssertionError(f"unexpected service {service}")

    monkeypatch.setattr(mod, "_boto3_client", _fake_client)
    mod._fake_ses = fake_ses  # stash for assertions
    return mod


def test_no_hardcoded_email_in_source():
    # No literal address pattern "<word>@<word>.<tld>" anywhere in the handler:
    # recipient/sender are configured purely via env vars / the event.
    import re

    source = _HANDLER_PATH.read_text(encoding="utf-8")
    assert not re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", source)


def test_requires_sender(handler_mod, monkeypatch):
    monkeypatch.delenv("SES_SENDER_EMAIL", raising=False)
    with pytest.raises(handler_mod.ReportEmailError):
        handler_mod.handler({"report": {"content": "{}"}}, None)


def test_requires_recipient(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.delenv("REPORT_RECIPIENT_EMAIL", raising=False)
    with pytest.raises(handler_mod.ReportEmailError):
        handler_mod.handler({"report": {"content": "{}"}}, None)


def test_inline_report_sent(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "rcpt@test.local")
    event = {"report": {"filename": "wily-report.json", "content": '{"findings": []}'}}
    result = handler_mod.handler(event, None)

    assert result["status"] == "sent"
    assert result["attachment"] == "wily-report.json"
    assert result["message_id"] == "fake-message-id"

    call = handler_mod._fake_ses.calls[0]
    assert call["Source"] == "sender@test.local"
    assert call["Destinations"] == ["rcpt@test.local"]
    msg = message_from_string(call["RawMessage"]["Data"])
    assert msg["To"] == "rcpt@test.local"
    # The attachment carries the report content.
    parts = [p for p in msg.walk() if p.get_filename() == "wily-report.json"]
    assert parts and b'"findings"' in parts[0].get_payload(decode=True)


def test_event_recipient_overrides_env(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "default@test.local")
    event = {
        "recipient": "override@test.local",
        "subject": "Custom subject",
        "report": {"content": "{}"},
    }
    handler_mod.handler(event, None)
    call = handler_mod._fake_ses.calls[0]
    assert call["Destinations"] == ["override@test.local"]
    msg = message_from_string(call["RawMessage"]["Data"])
    assert msg["Subject"] == "Custom subject"


def test_base64_inline_content(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "rcpt@test.local")
    raw = base64.b64encode(b"<html>report</html>").decode()
    event = {"report": {"filename": "r.html", "content": raw, "encoding": "base64"}}
    handler_mod.handler(event, None)
    call = handler_mod._fake_ses.calls[0]
    msg = message_from_string(call["RawMessage"]["Data"])
    parts = [p for p in msg.walk() if p.get_filename() == "r.html"]
    assert parts and parts[0].get_payload(decode=True) == b"<html>report</html>"


def test_s3_event_fetches_object(monkeypatch):
    mod = _load_handler()
    fake_ses = _FakeSes()
    fake_s3 = _FakeS3(body=b"{}", metadata={"recipient": "meta@test.local"})

    def _fake_client(service, region=None):
        return fake_ses if service == "ses" else fake_s3

    monkeypatch.setattr(mod, "_boto3_client", _fake_client)
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.delenv("REPORT_RECIPIENT_EMAIL", raising=False)

    event = {
        "Records": [
            {"s3": {"bucket": {"name": "wily-reports"}, "object": {"key": "run/report.html"}}}
        ]
    }
    result = mod.handler(event, None)
    assert result["attachment"] == "report.html"
    # Recipient resolved from the S3 object metadata.
    assert fake_ses.calls[0]["Destinations"] == ["meta@test.local"]


# ----------------------------------------------- Function URL / HTTP invocation


def _function_url_event(payload: dict, *, base64_body: bool = False) -> dict:
    """Shape a Lambda Function URL (API Gateway payload format 2.0) would
    actually send: the real JSON payload arrives as a *string* in 'body',
    alongside HTTP plumbing."""
    body = json.dumps(payload)
    if base64_body:
        body = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": "/",
        "headers": {"content-type": "application/json"},
        "requestContext": {"http": {"method": "POST"}},
        "body": body,
        "isBase64Encoded": base64_body,
    }


def test_function_url_event_is_unwrapped_and_sends(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    event = _function_url_event(
        {"recipient": "rcpt@test.local", "report": {"filename": "r.json", "content": "{}"}}
    )
    response = handler_mod.handler(event, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "sent"
    assert handler_mod._fake_ses.calls[0]["Destinations"] == ["rcpt@test.local"]


def test_function_url_base64_body_is_decoded(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    event = _function_url_event(
        {"recipient": "rcpt@test.local", "report": {"filename": "r.json", "content": "{}"}},
        base64_body=True,
    )
    response = handler_mod.handler(event, None)
    assert response["statusCode"] == 200


def test_function_url_missing_recipient_returns_400_not_crash(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.delenv("REPORT_RECIPIENT_EMAIL", raising=False)
    event = _function_url_event({"report": {"filename": "r.json", "content": "{}"}})
    response = handler_mod.handler(event, None)
    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert body["status"] == "error"
    assert "recipient" in body["message"].lower()


def test_function_url_ses_rejection_returns_400(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")

    def _rejecting_send_raw_email(**kwargs):
        raise RuntimeError("Email address is not verified.")

    handler_mod._fake_ses.send_raw_email = _rejecting_send_raw_email
    event = _function_url_event(
        {"recipient": "unverified@test.local", "report": {"filename": "r.json", "content": "{}"}}
    )
    response = handler_mod.handler(event, None)
    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert "not verified" in body["message"]


def test_function_url_malformed_body_returns_400_not_crash(monkeypatch):
    mod = _load_handler()
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    event = _function_url_event({})
    event["body"] = "{not valid json"
    response = mod.handler(event, None)
    assert response["statusCode"] == 400


def test_direct_invoke_shape_is_unaffected(handler_mod):
    """A plain direct-invoke event (no requestContext/body) keeps raising on
    failure instead of returning an HTTP-shaped response, same as before."""
    with pytest.raises(handler_mod.ReportEmailError):
        handler_mod.handler({"report": {"content": "{}"}}, None)  # no recipient, no env
