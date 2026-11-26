"""php2shell / PHP-to-shell exposure scanner.

"php2shell" (a.k.a. PHP2Shell) is the branding for a pair of critical PHP
core remote-code-execution flaws disclosed in October 2026:

  - CVE-2026-109618 - RCE via a use-after-free in the upload-progress
    unserializer, reachable through the ``session.upload_progress`` handler
    (enabled by default) using a ``multipart/form-data`` POST that sets the
    ``PHP_SESSION_UPLOAD_PROGRESS`` field; can also leak server memory.
  - CVE-2026-109619 - RCE via a use-after-free in fatal-error backtrace
    handling / an OPcache type-confusion bug.

Both are CVSS 9.2 (CVSS v4.0, PHP security team) / 9.8 (CVSS v3.1, NVD),
unauthenticated, and affect every web-serving SAPI (mod_php, PHP-FPM,
php-cgi, FrankenPHP, LiteSpeed). Fixed in 8.5.12 / 8.4.27 / 8.3.36 /
8.2.35; branches 8.1 and older are end-of-life with no official release.

DESIGN - detection, not exploitation (read the safety notes carefully):

  * The AUTOMATIC, default-on path is SAFE and NON-DESTRUCTIVE, exactly
    like a Nuclei CVE template. It confirms a host is *likely vulnerable*
    from benign signals only:
      1. Reading the PHP version banner the server itself advertises
         (``X-Powered-By: PHP/x.y.z`` or ``Server: ... PHP/x.y.z``) with a
         single GET, and comparing it against the patched-version floor.
      2. A GET presence check for the classic PHPUnit ``eval-stdin.php``
         PHP-to-shell path (CVE-2017-9841) - a GET with no body evaluates
         nothing, so it is harmless; only the HTTP status is read.
    It NEVER triggers the memory-corruption / use-after-free bug (that
    would crash the worker or run code), never uploads a webshell, never
    reads arbitrary files, and never runs attacker-controlled commands.

  * The ACTIVE behavioral confirmation (``attempt_active_confirmation``)
    is OPT-IN and gated, mirroring ``authz_bypass.confirm_destructive`` and
    ``timing_enum.confirm_timing_probe``. It requires BOTH
    ``PhpShellTarget.attempt_active_confirmation=True`` AND
    ``PhpShellScanner(confirm_exploit=True)`` - two independent signals, so
    it can never run on an automatic scan. Even then it sends only ONE
    benign, legitimate upload-progress-shaped request (the same shape a
    browser progress bar sends) carrying NO corruption payload, purely to
    corroborate that the vulnerable feature is reachable. It raises
    ``ScannerConfirmationError`` if requested without confirmation.

Every request goes through the shared, scope-enforcing ``HttpEngine``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.scanners.base import BaseScanner, Finding, ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine

# Patched version per supported PHP branch (major, minor) -> first fixed
# (major, minor, patch). A host on one of these branches but strictly below
# the listed patch is vulnerable to php2shell.
PHP_PATCHED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

# Branches with no official fix (end of life): 8.1 and anything older
# (8.0, 7.x, 5.x) - every release is vulnerable. Compared on (major, minor).
_EOL_VULNERABLE_MAX_BRANCH = (8, 1)

# A PHP version inside a banner: "PHP/8.3.12", "php/8.3". The patch group is
# optional because some servers advertise only the branch.
_PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)

# Response headers that commonly leak the PHP version, in order of preference.
_BANNER_HEADERS = ("x-powered-by", "server")

# Classic PHP-to-shell paths to check for mere EXPOSURE (safe GET presence).
# CVE-2017-9841: PHPUnit's eval-stdin.php evaluates the raw POST body as PHP;
# a GET with no body evaluates nothing, so probing its presence is harmless.
_DEFAULT_LEGACY_PATHS: tuple[str, ...] = (
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
    "/phpunit/src/Util/PHP/eval-stdin.php",
)


def parse_php_version(text: str) -> tuple[int, int, int] | None:
    """Extract a (major, minor, patch) PHP version from a banner string.

    When the banner carries only ``PHP/8.3`` (no patch level), the patch is
    reported as -1 so callers can tell "branch only" apart from a real
    ``.0`` patch and treat it conservatively.
    """
    m = _PHP_VERSION_RE.search(text or "")
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else -1
    return (major, minor, patch)


def php_version_status(
    version: tuple[int, int, int],
) -> tuple[str, tuple[int, int, int] | None]:
    """Classify a PHP version against the php2shell patch floors.

    Returns ``(status, patched_floor)`` where status is ``"vulnerable"``,
    ``"patched"`` or ``"unknown"`` (a branch newer than anything known, e.g.
    a future 8.6). ``patched_floor`` is the first fixed version for a
    supported branch, or ``None`` for an end-of-life branch with no fix.
    """
    branch = (version[0], version[1])
    floor = PHP_PATCHED_VERSIONS.get(branch)
    if floor is not None:
        # A branch-only banner ("PHP/8.3", patch == -1) cannot be proven
        # patched, so it is treated as vulnerable (conservative).
        return ("vulnerable" if version < floor else "patched"), floor
    if branch <= _EOL_VULNERABLE_MAX_BRANCH:
        return "vulnerable", None
    return "unknown", None


@dataclass
class PhpShellTarget:
    """A single host/base URL to check for php2shell exposure."""

    url: str
    # Also GET-probe the classic PHP-to-shell paths (CVE-2017-9841) for mere
    # exposure. Safe (GET presence only), so on by default.
    probe_legacy_paths: bool = True
    legacy_paths: list[str] = field(
        default_factory=lambda: list(_DEFAULT_LEGACY_PATHS)
    )
    # ACTIVE behavioral confirmation of the session.upload_progress trigger
    # surface (CVE-2026-109618). Opt-in and gated: requires BOTH this True AND
    # PhpShellScanner(confirm_exploit=True), so it can never run automatically.
    attempt_active_confirmation: bool = False


class PhpShellScanner(BaseScanner):
    name = "php_shell"
    requires_tenant_pair = False
    # Safe by construction with the default target (banner read + GET presence
    # only). The active behavioral confirmation is a separate opt-in that must
    # be enabled via confirm_exploit below.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None,
        http_engine: HttpEngine | None = None,
        confirm_exploit: bool = False,
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)
        self._confirm_exploit = confirm_exploit

    # --- safe banner detection -------------------------------------------
    def _detect_php_version(
        self, target: PhpShellTarget
    ) -> tuple[tuple[int, int, int] | None, str | None]:
        try:
            resp = self.http.request(method="GET", url=target.url, headers={})
        except Exception:
            return None, None
        headers = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
        for name in _BANNER_HEADERS:
            value = headers.get(name)
            if not value:
                continue
            version = parse_php_version(value)
            if version is not None:
                return version, name
        return None, None

    def _version_finding(
        self,
        target: PhpShellTarget,
        version: tuple[int, int, int],
        floor: tuple[int, int, int] | None,
        source: str | None,
        confirmed: bool,
    ) -> Finding:
        vstr = f"{version[0]}.{version[1]}" + (
            f".{version[2]}" if version[2] >= 0 else ""
        )
        # Version banner alone is a safe, inferential signal (banners can be
        # removed/spoofed, and some distros backport the fix WITHOUT bumping
        # the version string - a false-positive source), so confidence stays
        # moderate. The opt-in active check only lifts it to 0.8.
        confidence = 0.8 if confirmed else 0.6
        return Finding(
            asset=target.url,
            category="php2shell-cve-2026-109618-109619",
            severity="critical",
            confidence=confidence,
            discovery_source="scanner",
            evidence={
                "technique": "php_version_banner",
                "php_version": vstr,
                "branch": f"{version[0]}.{version[1]}",
                "patched_version": (
                    f"{floor[0]}.{floor[1]}.{floor[2]}" if floor else None
                ),
                "banner_source_header": source,
                "active_upload_progress_confirmation": confirmed,
                "note": (
                    "Detected from the PHP version the server advertises - "
                    "a benign, non-destructive signal; the memory-corruption "
                    "/ use-after-free bug was never triggered. A distribution "
                    "may have backported the fix without changing the version "
                    "string, so confirm with the distro advisory or `php -v`."
                ),
            },
            remediation=(
                "Upgrade PHP to a patched release (8.5.12 / 8.4.27 / 8.3.36 / "
                "8.2.35, or your distro's backported package). For end-of-life "
                "branches (8.1 and older) migrate to a supported branch. As a "
                "partial interim mitigation disable session.upload_progress "
                "(session.upload_progress.enabled=0), which reduces the "
                "CVE-2026-109618 (upload-progress) trigger surface; patching "
                "remains the only full fix."
            ),
        )

    # --- safe legacy-path exposure (CVE-2017-9841) -----------------------
    def _probe_legacy_paths(self, target: PhpShellTarget) -> list[Finding]:
        findings: list[Finding] = []
        base = target.url.rstrip("/")
        for path in target.legacy_paths:
            url = base + path
            try:
                resp = self.http.request(method="GET", url=url, headers={})
            except Exception:
                continue
            if resp.status_code == 200:
                findings.append(
                    Finding(
                        asset=url,
                        category="php-rce-cve-2017-9841",
                        severity="high",
                        confidence=0.5,
                        discovery_source="scanner",
                        evidence={
                            "technique": "phpunit_eval_stdin_exposure",
                            "path": path,
                            "response_status": resp.status_code,
                            "note": (
                                "The PHPUnit eval-stdin.php endpoint is "
                                "reachable (HTTP 200). This file evaluates the "
                                "raw POST body as PHP (CVE-2017-9841), a classic "
                                "PHP-to-shell path. Detected by safe GET presence "
                                "only - no payload was sent."
                            ),
                        },
                        remediation=(
                            "Remove PHPUnit and other dev dependencies from the "
                            "production document root, or block access to "
                            "/vendor. Never ship vendor/ to an internet-facing "
                            "web root."
                        ),
                    )
                )
                # One exposure finding is enough across the path variants.
                break
        return findings

    # --- opt-in, gated active confirmation -------------------------------
    def _probe_upload_progress(self, target: PhpShellTarget) -> bool:
        """Send ONE benign, legitimate upload-progress-shaped request to
        corroborate that the session.upload_progress handler is reachable.

        This is the SAME shape a browser's upload progress bar sends: it sets
        the ``PHP_SESSION_UPLOAD_PROGRESS`` field and a tiny harmless text
        part. It carries NO memory-corruption / use-after-free payload, so it
        cannot crash the worker or execute code. Only the response status is
        read; no reflected content is ever interpreted as a command result.
        """
        marker = f"wily-php2shell-probe-{secrets.token_hex(4)}"
        boundary = f"----wily{secrets.token_hex(8)}"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            f"\r\n\r\n{marker}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{marker}.txt"'
            "\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "wily-benign-marker\r\n"
            f"--{boundary}--\r\n"
        )
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={secrets.token_hex(13)}",
        }
        try:
            resp = self.http.request(
                method="POST", url=target.url, headers=headers, body=body
            )
        except Exception:
            return False
        # Accepted without a server error => PHP session handling is active and
        # the benign upload-progress request was processed. A 5xx (possible
        # crash) is NOT treated as confirmation.
        return resp.status_code < 500

    def run(self, target: PhpShellTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Opt-in active confirmation gate (two independent signals required),
        # mirroring authz_bypass. It only ever CORROBORATES a vulnerable
        # version banner; the handler being reachable is not a vuln on its own.
        upload_progress_reachable = False
        if target.attempt_active_confirmation:
            if not self._confirm_exploit:
                raise ScannerConfirmationError(
                    "PhpShellTarget.attempt_active_confirmation=True but "
                    "PhpShellScanner was built without confirm_exploit=True. "
                    "The active check sends a request to the target's "
                    "session.upload_progress handler and requires an explicit, "
                    "separate confirmation (--php-shell-confirm) before it runs. "
                    "The default automatic scan uses safe banner detection only "
                    "and needs no confirmation."
                )
            upload_progress_reachable = self._probe_upload_progress(target)

        version, source = self._detect_php_version(target)
        if version is not None:
            status, floor = php_version_status(version)
            if status == "vulnerable":
                findings.append(
                    self._version_finding(
                        target, version, floor, source, upload_progress_reachable
                    )
                )

        if target.probe_legacy_paths:
            findings += self._probe_legacy_paths(target)

        return findings
