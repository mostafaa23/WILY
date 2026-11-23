"""Live JWT auto-harvest: pull access tokens the target itself exposes.

A plain ``wily scan <domain>`` used to light up the JWT Tampering module only
when the tester passed ``--token`` by hand. In practice a real app hands its
own JWTs out all the time - in a login response body, in a ``Set-Cookie``
value, echoed back in a header, or baked into a JS bundle. This module does a
bounded, READ-ONLY (GET-only) pass over the in-scope endpoints the scan
already discovered and extracts any valid JWT it finds, so the JWT scanner can
then run automatically against the token the target volunteered.

Detection reuses the shared helpers in :mod:`wily.recon.traffic_import`
(``find_jwts_in_text`` / ``is_valid_jwt``) - the exact same JWT validation the
imported-traffic path uses, so there is a single source of truth for "is this
actually a JWT" rather than a second, drifting extractor.

Safety:
  * Every fetch goes through the shared, scope-enforcing ``HttpEngine`` - an
    out-of-scope or private/metadata host is refused there, not here.
  * Nothing but GET is issued; no payloads, no mutation.
  * Harvested tokens are never logged raw - :func:`redact_jwt` masks them.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from wily.recon.traffic_import import find_jwts_in_text

__all__ = ["HarvestedToken", "harvest_from_response", "harvest_tokens", "redact_jwt"]

# Path keywords that most often hand out or carry a token - fetched first so a
# small per-run budget still lands on the places a JWT actually lives.
_AUTH_PATH_HINTS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "oauth",
    "sso",
    "token",
    "session",
    "jwt",
    "/me",
    "account",
    "user",
    "profile",
)

_JS_SUFFIXES: tuple[str, ...] = (".js", ".mjs", ".cjs")

# Default cap on how many URLs the harvest pass fetches. Small on purpose: this
# is a quick opportunistic sweep, not a second crawl.
DEFAULT_MAX_FETCH = 30


@dataclass(frozen=True)
class HarvestedToken:
    """One JWT found live, plus a human-readable, REDACTED-safe provenance."""

    token: str
    source: str  # e.g. "Set-Cookie header on http://host/login"


def redact_jwt(token: str) -> str:
    """A safe one-line label for a harvested JWT - never the raw token.

    Shows the (non-secret) algorithm from the header and the token length, with
    only the fixed ``eyJ`` prefix echoed. The payload and signature - the parts
    that are actually sensitive - are never included.
    """
    alg = "?"
    parts = token.split(".") if isinstance(token, str) else []
    if parts:
        # Local import avoids a module-level cycle and keeps the helper cheap.
        from wily.recon.traffic_import import _b64url_json

        header = _b64url_json(parts[0])
        if header is not None and header.get("alg") is not None:
            alg = str(header.get("alg"))
    length = len(token) if isinstance(token, str) else 0
    return f"eyJ...[JWT alg={alg}, {length} chars]"


def harvest_from_response(response: object, url: str) -> list[HarvestedToken]:
    """Extract validated JWTs from one HTTP response (headers + body).

    Response headers are scanned first and individually, so the provenance can
    name the exact header (``Set-Cookie``, ``Authorization``, ``X-Auth-Token``,
    ...); the body is scanned last. A token seen in more than one place in the
    same response is returned once, labelled by where it was first seen.
    """
    out: list[HarvestedToken] = []
    seen: set[str] = set()

    headers = getattr(response, "headers", None) or {}
    try:
        items = headers.items()
    except AttributeError:
        items = []
    for name, value in items:
        if not isinstance(value, str):
            value = str(value)
        for token in find_jwts_in_text(value):
            if token in seen:
                continue
            seen.add(token)
            out.append(HarvestedToken(token=token, source=f"{name} header on {url}"))

    body = getattr(response, "text", "") or ""
    for token in find_jwts_in_text(body):
        if token in seen:
            continue
        seen.add(token)
        out.append(HarvestedToken(token=token, source=f"response body on {url}"))

    return out


def _prioritize(target_url: str, endpoints: list[str], scope: object) -> list[str]:
    """Order URLs so the token-likely ones are fetched within a small budget.

    The base target first (a login/landing response is the single most common
    place a token is handed out), then in-scope auth-ish paths and JS bundles,
    then everything else in scope. De-duplicated, order-preserving.
    """
    prioritized: list[str] = []
    rest: list[str] = []
    for endpoint in endpoints:
        if scope is not None:
            try:
                if not scope.is_in_scope(endpoint):
                    continue
            except Exception:
                continue
        low = endpoint.lower()
        path = urlparse(endpoint).path.lower()
        if any(hint in low for hint in _AUTH_PATH_HINTS) or path.endswith(_JS_SUFFIXES):
            prioritized.append(endpoint)
        else:
            rest.append(endpoint)

    ordered: list[str] = []
    for url in [target_url, *prioritized, *rest]:
        if url and url not in ordered:
            ordered.append(url)
    return ordered


def harvest_tokens(
    target_url: str,
    endpoints: list[str],
    scope: object,
    http_engine: object,
    *,
    max_fetch: int = DEFAULT_MAX_FETCH,
) -> list[HarvestedToken]:
    """Fetch a bounded set of in-scope URLs and return every JWT they expose.

    Synchronous and GET-only. Intended to be offloaded with
    ``asyncio.to_thread`` by the orchestrator, exactly like parameter
    discovery, so it never blocks the event loop. Any per-URL transport or
    scope failure is swallowed - a token harvest must never abort a scan.
    """
    ordered = _prioritize(target_url, endpoints, scope)
    results: list[HarvestedToken] = []
    seen_tokens: set[str] = set()

    for url in ordered[: max(1, max_fetch)]:
        try:
            response = http_engine.request(method="GET", url=url, headers={})
        except Exception:
            continue
        for harvested in harvest_from_response(response, url):
            if harvested.token in seen_tokens:
                continue
            seen_tokens.add(harvested.token)
            results.append(harvested)

    return results
