"""Optional notification backends (e.g. emailing a finished scan report)."""

from wily.notify.email_report import (
    DEFAULT_REPORT_ENDPOINT,
    ReportNotificationError,
    package_reports,
    send_report_via_http,
)

__all__ = [
    "DEFAULT_REPORT_ENDPOINT",
    "ReportNotificationError",
    "package_reports",
    "send_report_via_http",
]
