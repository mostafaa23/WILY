"""Missing / weak HTTP security headers scanner (OWASP A02:2025 - Security
Misconfiguration).

One GET to each in-scope origin, then a pure inspection of the response
headers:

* **missing** - ``Content-Security-Policy``, ``X-Frame-Options`` (satisfied by
  a CSP ``frame-ancestors`` directive), ``X-Content-Type-Options``,
  ``Referrer-Policy``, ``Permissions-Policy`` and, on HTTPS responses only,
  ``Strict-Transport-Security``. HSTS is owned here: the TLS scanner works at
  the socket level and never reads HTTP headers.
* **weak** - a CSP whose effective ``script-src`` / ``default-src`` allows
  ``'unsafe-inline'`` (unless neutralised by a nonce/hash), ``'unsafe-eval'``
  or a bare ``*``; a report-only CSP; ``X-Content-Type-Options`` other than
  ``nosniff``; ``Referrer-Policy: unsafe-url``; an HSTS ``max-age`` shorter
  than 180 days.
* **info_disclosure** - ``Server`` / ``X-Powered-By`` (and the ASP.NET version
  headers) advertising a product version.

The document-only headers (CSP, X-Frame-Options, Referrer-Policy,
Permissions-Policy) are checked only when the response is HTML - a JSON API
root missing a CSP is noise, not a finding.

All results for one origin are grouped into ONE finding
(``security-misconfig-headers``) instead of one per header.

Safety: a single read-only GET through the injected scope-enforcing
``HttpEngine``. No body is sent, nothing is written. No confirmation flag.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

logger = logging.getLogger("wily.security_headers")

CATEGORY = "security-misconfig-headers"

# HSTS max-age below this (180 days) is reported as weak - the usual
# baseline (Mozilla Observatory / hstspreload.org require >= 1 year for
# preload, but 6 months is the commonly accepted minimum).
_HSTS_MIN_MAX_AGE = 15_552_000

# Missing any of these (or a weak value in them) makes the finding medium;
# gaps limited to the remaining headers / banners stay low.
_CORE_HEADERS = frozenset({
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
})

# Recommended values, used to build the remediation text.
RECOMMENDED: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY (or SAMEORIGIN), or CSP frame-ancestors",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# Headers that disclose the server stack. Server / X-Powered-By are only
# reported when they carry a version number ("nginx" alone is harmless);
# the ASP.NET headers exist only to state a version, so always count.
_BANNER_HEADERS = ("Server", "X-Powered-By")
_ALWAYS_VERSION_HEADERS = ("X-AspNet-Version", "X-AspNetMvc-Version")
_VERSION_RE = re.compile(r"\d+\.\d+|/\s*\d")

_NONCE_OR_HASH_RE = re.compile(r"^'(?:nonce-|sha256-|sha384-|sha512-)", re.IGNORECASE)


@dataclass
class SecurityHeadersTarget:
    origin: str  # scheme://host[:port]


@dataclass
class HeaderAssessment:
    missing: list[str] = field(default_factory=list)
    weak: dict[str, str] = field(default_factory=dict)
    info_disclosure: dict[str, str] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (self.missing or self.weak or self.info_disclosure)


def _header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup over a plain dict."""
    lname = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == lname:
            return str(value)
    return None


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Split a CSP into ``{directive: [source, ...]}`` (lower-cased names,
    first occurrence wins - as browsers do)."""
    directives: dict[str, list[str]] = {}
    for part in (policy or "").split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = tokens[1:]
    return directives


def csp_weaknesses(policy: str) -> list[str]:
    """Return the weak sources in the *effective* script policy: ``script-src``
    when present, otherwise ``default-src`` (which is what browsers fall back
    to). ``'unsafe-inline'`` next to a nonce/hash is ignored by CSP2+
    browsers, so it is not reported in that case."""
    directives = parse_csp(policy)
    problems: list[str] = []
    for name in ("script-src", "default-src"):
        if name not in directives:
            continue
        sources = [s.lower() for s in directives[name]]
        has_nonce_or_hash = any(_NONCE_OR_HASH_RE.match(s) for s in sources)
        if "'unsafe-inline'" in sources and not has_nonce_or_hash:
            problems.append(f"{name} allows 'unsafe-inline'")
        if "'unsafe-eval'" in sources:
            problems.append(f"{name} allows 'unsafe-eval'")
        if "*" in sources:
            problems.append(f"{name} allows any origin (*)")
        if name == "script-src":
            # script-src overrides default-src for scripts; stop here.
            break
    return problems


def _is_html(headers: dict) -> bool:
    ctype = (_header(headers, "Content-Type") or "").lower()
    # No Content-Type at all: browsers will sniff it - treat as a document.
    return not ctype or "html" in ctype


def _hsts_max_age(value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value or "", re.IGNORECASE)
    return int(m.group(1)) if m else None


def evaluate_headers(headers: dict, final_url: str) -> HeaderAssessment:
    """Pure header evaluation - see the module docstring for the rules."""
    result = HeaderAssessment()
    is_https = urlparse(final_url or "").scheme.lower() == "https"
    is_html = _is_html(headers)

    if is_https:
        hsts = _header(headers, "Strict-Transport-Security")
        if hsts is None:
            result.missing.append("Strict-Transport-Security")
        else:
            max_age = _hsts_max_age(hsts)
            if max_age is None or max_age < _HSTS_MIN_MAX_AGE:
                result.weak["Strict-Transport-Security"] = (
                    f"max-age is {'missing' if max_age is None else max_age} "
                    f"(< {_HSTS_MIN_MAX_AGE}s / 180 days)"
                )

    xcto = _header(headers, "X-Content-Type-Options")
    if xcto is None:
        result.missing.append("X-Content-Type-Options")
    elif xcto.strip().lower() != "nosniff":
        result.weak["X-Content-Type-Options"] = f"value is {xcto.strip()!r}, expected 'nosniff'"

    if is_html:
        csp = _header(headers, "Content-Security-Policy")
        if csp is None:
            result.missing.append("Content-Security-Policy")
            if _header(headers, "Content-Security-Policy-Report-Only") is not None:
                result.weak["Content-Security-Policy"] = (
                    "only Content-Security-Policy-Report-Only is set (not enforced)"
                )
        else:
            problems = csp_weaknesses(csp)
            if problems:
                result.weak["Content-Security-Policy"] = "; ".join(problems)

        frame_ancestors = "frame-ancestors" in parse_csp(csp or "")
        if _header(headers, "X-Frame-Options") is None and not frame_ancestors:
            result.missing.append("X-Frame-Options")

        referrer = _header(headers, "Referrer-Policy")
        if referrer is None:
            result.missing.append("Referrer-Policy")
        elif "unsafe-url" in referrer.lower():
            result.weak["Referrer-Policy"] = "unsafe-url leaks full URLs cross-origin"

        # The legacy Feature-Policy header is accepted as the same control.
        if (
            _header(headers, "Permissions-Policy") is None
            and _header(headers, "Feature-Policy") is None
        ):
            result.missing.append("Permissions-Policy")

    for name in _BANNER_HEADERS:
        value = _header(headers, name)
        if value and _VERSION_RE.search(value):
            result.info_disclosure[name] = value.strip()[:200]
    for name in _ALWAYS_VERSION_HEADERS:
        value = _header(headers, name)
        if value:
            result.info_disclosure[name] = value.strip()[:200]

    return result


def severity_for(assessment: HeaderAssessment) -> str:
    """medium when a core protection (CSP, HSTS, frame protection, nosniff)
    is missing or weak; low when only the softer headers or a version
    banner are at issue."""
    touched = set(assessment.missing) | set(assessment.weak)
    return "medium" if touched & _CORE_HEADERS else "low"


def build_remediation(assessment: HeaderAssessment) -> str:
    lines: list[str] = []
    for name in list(assessment.missing) + [
        n for n in assessment.weak if n not in assessment.missing
    ]:
        rec = RECOMMENDED.get(name)
        if rec:
            lines.append(f"{name}: {rec}")
    if assessment.info_disclosure:
        lines.append(
            "Remove or genericise version banners ("
            + ", ".join(assessment.info_disclosure)
            + "), e.g. nginx `server_tokens off;`, Apache `ServerTokens Prod`, "
            "PHP `expose_php = Off`."
        )
    return "Set the following response headers on every page: " + " | ".join(lines)


class SecurityHeadersScanner(BaseScanner):
    name = "security_headers"
    requires_tenant_pair = False
    # A single GET of the origin; no owned-infra gate needed.
    requires_owned_infra = False

    def __init__(self, scope_manager=None, http_engine: HttpEngine | None = None) -> None:
        self.scope = scope_manager
        if http_engine is None and scope_manager is not None:
            http_engine = HttpEngine(scope_manager=scope_manager)
        self.http = http_engine

    def run(self, target: SecurityHeadersTarget) -> list[Finding]:
        if self.http is None:
            return []
        try:
            resp = self.http.request(method="GET", url=target.origin, headers={})
        except Exception as exc:  # scope refusal, timeout, connection error
            logger.info("security_headers: GET %s failed (%s)", target.origin, exc)
            return []

        # A 5xx is likely a transient error page from a proxy, not the app's
        # real header configuration - don't judge it.
        if resp.status_code >= 500:
            return []

        final_url = getattr(resp, "url", None) or target.origin
        assessment = evaluate_headers(resp.headers or {}, final_url)
        if assessment.empty:
            return []

        return [
            Finding(
                asset=target.origin,
                category=CATEGORY,
                severity=severity_for(assessment),
                # Header presence is directly observed, not inferred.
                confidence=0.9,
                discovery_source="scanner",
                evidence={
                    "missing": assessment.missing,
                    "weak": assessment.weak,
                    "info_disclosure": assessment.info_disclosure,
                    "status_code": resp.status_code,
                    "final_url": final_url,
                    "content_type": _header(resp.headers or {}, "Content-Type"),
                },
                remediation=build_remediation(assessment),
            )
        ]
