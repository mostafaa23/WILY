"""Optional notification backends (e.g. emailing a finished scan report)."""

from wily.notify.email_report import (
    ReportNotificationError,
    package_reports,
    send_report_via_lambda,
)

__all__ = [
    "ReportNotificationError",
    "package_reports",
    "send_report_via_lambda",
]
