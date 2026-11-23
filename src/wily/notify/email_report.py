"""Email a finished scan report by invoking the deployed AWS Lambda
(``lambda/send_report``), which delivers it via Amazon SES.

A full scan of many targets can take a while, so Wily can hand the final
report off to be emailed when it finishes - "leave your address and we'll send
it to you". The CLI does not talk to SES directly: it invokes the Lambda with
the same direct-invoke event shape that handler already accepts, so the email
address, sender and credentials all stay in the Lambda's own configuration and
nothing sensitive is baked into the client.

``boto3`` is imported lazily, so this module (and its tests) load without it;
install the optional dependency with ``pip install "wily-scanner[aws]"`` to use
the feature. Configuration:

  --email ADDRESS / passed recipient   who receives the report (required)
  --report-lambda NAME / WILY_REPORT_LAMBDA   the Lambda function to invoke
  AWS_REGION                            region for the Lambda client (optional)

Credentials come from the caller's normal AWS environment (profile, env vars,
or instance role) - never from anything stored here.
"""

from __future__ import annotations

import base64
import io
import json
import os
import zipfile
from pathlib import Path


class ReportNotificationError(RuntimeError):
    """Raised when the report cannot be packaged or handed to the Lambda.

    The CLI catches this and prints a clear message; a notification failure
    never changes the scan's own exit code.
    """


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else value


def _lambda_client(region: str | None):
    # Imported lazily so the module loads without boto3 and tests can patch
    # this function to inject a fake client.
    import boto3

    return boto3.client("lambda", region_name=region) if region else boto3.client("lambda")


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


def send_report_via_lambda(
    *,
    recipient: str,
    report_path: str | Path,
    function_name: str | None = None,
    subject: str | None = None,
    region: str | None = None,
    client=None,
) -> dict:
    """Package the report and invoke the send-report Lambda to email it.

    ``function_name`` falls back to ``WILY_REPORT_LAMBDA`` and ``region`` to
    ``AWS_REGION``. ``client`` is injectable for testing. Returns a small
    result dict; raises :class:`ReportNotificationError` on any misconfiguration
    or Lambda-side error.
    """
    function_name = function_name or _env("WILY_REPORT_LAMBDA")
    if not function_name:
        raise ReportNotificationError(
            "no Lambda function configured: pass --report-lambda NAME or set "
            "WILY_REPORT_LAMBDA to the deployed send-report function."
        )
    if not recipient:
        raise ReportNotificationError("no recipient email address was given.")

    region = region or _env("AWS_REGION")
    filename, content = package_reports(report_path)

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

    if client is None:
        try:
            client = _lambda_client(region)
        except ImportError as exc:  # boto3 not installed
            raise ReportNotificationError(
                "boto3 is required to email reports; install it with "
                '`pip install "wily-scanner[aws]"`.'
            ) from exc

    try:
        response = client.invoke(
            FunctionName=function_name,
            Payload=json.dumps(event).encode("utf-8"),
        )
    except Exception as exc:  # network / auth / no-such-function
        raise ReportNotificationError(
            f"invoking Lambda '{function_name}' failed: {exc}"
        ) from exc

    raw = response.get("Payload")
    body = raw.read() if hasattr(raw, "read") else (raw or b"")
    if isinstance(body, str):
        body = body.encode("utf-8")
    detail = body.decode("utf-8", "replace")[:500]

    if response.get("FunctionError"):
        raise ReportNotificationError(
            f"Lambda '{function_name}' returned an error: {detail}"
        )

    return {
        "function": function_name,
        "attachment": filename,
        "bytes": len(content),
        "lambda_response": detail,
    }
