"""Email a finished scan report via the deployed Wily send-report service,
which delivers it through Amazon SES.

A full scan of many targets can take a while, so Wily can hand the final
report off to be emailed when it finishes - "leave your address and we'll send
it to you". This is a plain HTTPS POST to a public Lambda Function URL: no AWS
account, credentials, or extra dependency is needed by whoever runs `wily` -
only internet access. The sender address, SES credentials and everything
AWS-side live entirely in the deployed Lambda's own configuration; nothing
sensitive is baked into the client, and the request carries only the
recipient address the user typed and the report bytes.

``DEFAULT_REPORT_ENDPOINT`` is the project's own hosted instance, so this
works out of the box for anyone who installs wily-scanner. Point it elsewhere
with ``--report-endpoint`` / ``$WILY_REPORT_ENDPOINT`` to use a self-hosted
deployment instead (see ``lambda/send_report/``).
"""

from __future__ import annotations

import base64
import io
import json
import os
import zipfile
from pathlib import Path

import requests

# The project's own publicly reachable send-report Lambda (Function URL, no
# auth required - it only ever emails the recipient the caller supplies).
DEFAULT_REPORT_ENDPOINT = "https://xyyawpfjebtsvqgmglxprtfkly0apbty.lambda-url.eu-north-1.on.aws/"


class ReportNotificationError(RuntimeError):
    """Raised when the report cannot be packaged or handed off to be emailed.

    The CLI catches this and prints a clear message; a notification failure
    never changes the scan's own exit code.
    """


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else value


def package_reports(path: str | Path) -> tuple[str, bytes]:
    """Turn a scan's output into one attachment.

    A directory (the ``--output-dir`` of a multi-target scan) is zipped into
    ``wily-reports.zip``; a single report file is read as-is. Returns
    ``(filename, content_bytes)``.
    """
    path = Path(path)
    if not path.exists():
        raise ReportNotificationError(f"nothing to email: {path} does not exist")

    if path.is_dir():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            files = [p for p in sorted(path.rglob("*")) if p.is_file()]
            if not files:
                raise ReportNotificationError(f"nothing to email: {path} is empty")
            for file in files:
                archive.write(file, file.relative_to(path).as_posix())
        return "wily-reports.zip", buffer.getvalue()

    return path.name, path.read_bytes()


def _build_event(recipient: str, filename: str, content: bytes, subject: str | None) -> dict:
    event: dict = {
        "recipient": recipient,
        "report": {
            "filename": filename,
            "content": base64.b64encode(content).decode("ascii"),
            "encoding": "base64",
        },
    }
    if subject:
        event["subject"] = subject
    return event


def send_report_via_http(
    *,
    recipient: str,
    report_path: str | Path,
    endpoint: str | None = None,
    subject: str | None = None,
    timeout: float = 30.0,
    http_post=None,
) -> dict:
    """Package the report and POST it to a send-report Function URL.

    ``endpoint`` falls back to ``$WILY_REPORT_ENDPOINT``, then to the
    project's own :data:`DEFAULT_REPORT_ENDPOINT` - so this works with no
    configuration at all unless a self-hosted deployment is wanted.
    ``http_post`` is injectable for testing: ``(url, json_body, timeout) ->
    (status_code, response_text)``. Raises :class:`ReportNotificationError` on
    any misconfiguration or server-side error.
    """
    if not recipient:
        raise ReportNotificationError("no recipient email address was given.")

    endpoint = endpoint or _env("WILY_REPORT_ENDPOINT") or DEFAULT_REPORT_ENDPOINT
    filename, content = package_reports(report_path)
    event = _build_event(recipient, filename, content, subject)

    if http_post is None:

        def http_post(url: str, body: dict, timeout: float) -> tuple[int, str]:
            resp = requests.post(url, json=body, timeout=timeout)
            return resp.status_code, resp.text

    try:
        status, text = http_post(endpoint, event, timeout)
    except Exception as exc:  # network error, timeout, DNS, ...
        raise ReportNotificationError(f"could not reach {endpoint}: {exc}") from exc

    if status >= 400:
        raise ReportNotificationError(
            f"report service returned HTTP {status}: {text[:500]}"
        )

    try:
        data = json.loads(text) if text else {}
    except ValueError:
        data = {}

    if data.get("status") != "sent":
        raise ReportNotificationError(
            f"report service did not confirm delivery: {text[:500]}"
        )

    return {
        "endpoint": endpoint,
        "attachment": filename,
        "bytes": len(content),
        "message_id": data.get("message_id"),
    }
