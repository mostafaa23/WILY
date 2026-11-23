"""File-based session/token pool that auto-feeds BOLA identities.

BOLA testing needs >=2 working identities. Today they are supplied by hand,
one ``--identity name=HeaderValue`` per account. This module lets a tester
instead keep a *pool* of saved tokens/cookies in a file, have Wily verify
which ones still work (a cheap read-only GET that returns 200 against an
in-scope endpoint), and auto-select the first two live identities to feed the
existing :class:`~wily.scanners.bola.BolaTester`.

Pool file format (one identity per line, blank and ``#`` comment lines ignored)::

    # name = header spec, OR a bare JWT
    tenant_a = Authorization: Bearer eyJhbGciOi...
    tenant_b = Cookie: session=abc123
    tenant_c = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5In0.sig   # bare JWT

Each line is ``name=value``. ``value`` is read as:

* an explicit ``Header-Name: header value`` spec (``Authorization: Bearer ...``,
  ``Cookie: session=...``, ``X-Api-Key: ...``) - taken verbatim; or
* a bare token, optionally with a ``Bearer `` prefix - accepted only when it
  passes :func:`~wily.recon.traffic_import.is_valid_jwt`, so a dotted non-JWT
  string is never mistaken for a credential, and sent as ``Authorization:
  Bearer <token>``.

Safety:
  * Liveness probes go through the shared, scope-enforcing ``HttpEngine`` - an
    out-of-scope or private/metadata host is refused there, not here.
  * Nothing but GET is issued; no payloads, no mutation. Bounded: stops once
    enough live identities are found.
  * Raw tokens are never logged - a JWT is labelled via :func:`redact_jwt`, any
    other header value by its name only. Test/lab tokens only; the tester
    supplies the file.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from wily.recon.token_harvest import redact_jwt
from wily.recon.traffic_import import is_valid_jwt
from wily.scanners.bola import Identity

__all__ = [
    "PooledIdentity",
    "load_token_pool",
    "parse_token_pool",
    "select_live_identities",
]

logger = logging.getLogger("wily.token_pool")

# A header spec: "Header-Name: value". The name is a conservative HTTP token
# (letters/digits/hyphen); everything after the first ": " is the value.
_HEADER_SPEC_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9-]*)\s*:\s*(?P<value>.+)$")

# Default cap on how many pooled identities we probe for liveness - a pool is
# meant to be small (a handful of test accounts), and BOLA only needs two.
DEFAULT_MAX_PROBES = 20


@dataclass(frozen=True)
class PooledIdentity:
    """One parsed pool entry: a name, the header(s) to send, and a REDACTED
    label safe to print. ``headers`` is sent as-is on the liveness probe and,
    once selected, on every BOLA replay for this identity."""

    name: str
    headers: dict[str, str]
    label: str


def _redacted_label(header_name: str, header_value: str) -> str:
    """A log-safe description of a header - never the raw secret.

    An ``Authorization: Bearer <JWT>`` is summarised by :func:`redact_jwt`
    (alg + length). Any other header is named but its value withheld.
    """
    if header_name.lower() == "authorization":
        token = header_value[7:].strip() if header_value[:7].lower() == "bearer " else header_value
        if is_valid_jwt(token):
            return f"Authorization: Bearer {redact_jwt(token)}"
        return "Authorization header (value withheld)"
    return f"{header_name} header (value withheld)"


def parse_token_pool(text: str) -> list[PooledIdentity]:
    """Parse the pool file's text into :class:`PooledIdentity` entries.

    Tolerant of blank lines and ``#`` comments. A line without ``=``, with an
    empty name, or whose bare (non-header-spec) value is not a valid JWT, is
    skipped rather than raising - a malformed line must never abort a scan.
    Order-preserving; a later duplicate name wins (last definition stands).
    """
    out: list[PooledIdentity] = []
    by_name: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or not value:
            continue

        match = _HEADER_SPEC_RE.match(value)
        if match:
            header_name = match.group("name")
            header_value = match.group("value").strip()
            headers = {header_name: header_value}
            label = _redacted_label(header_name, header_value)
        else:
            # Bare token: accept only a real JWT (optionally "Bearer <jwt>").
            token = value[7:].strip() if value[:7].lower() == "bearer " else value
            if not is_valid_jwt(token):
                logger.debug("token pool: skipping non-JWT bare value for %r", name)
                continue
            headers = {"Authorization": f"Bearer {token}"}
            label = f"Authorization: Bearer {redact_jwt(token)}"

        entry = PooledIdentity(name=name, headers=headers, label=label)
        if name in by_name:
            out[by_name[name]] = entry
        else:
            by_name[name] = len(out)
            out.append(entry)
    return out


def load_token_pool(path: str) -> list[PooledIdentity]:
    """Read and parse a pool file. Returns ``[]`` if it can't be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        logger.warning("token pool: could not read %s: %s", path, exc)
        return []
    return parse_token_pool(text)


def select_live_identities(
    pool: list[PooledIdentity],
    probe_url: str,
    http_engine: object,
    *,
    want: int = 2,
    max_probes: int = DEFAULT_MAX_PROBES,
) -> list[Identity]:
    """Probe pooled identities read-only and return the first ``want`` that are live.

    For each pooled identity (up to ``max_probes``) one GET is sent to
    ``probe_url`` through the shared scope-enforcing ``http_engine``; an entry
    is kept only when the response status is 200. Probing stops as soon as
    ``want`` live identities are found, so a healthy pool costs just two
    requests. Any per-identity transport or scope failure is swallowed - it
    simply means "not live". Returns ready-to-use
    :class:`~wily.scanners.bola.Identity` objects (JWT seed-claim harvesting
    happens in ``Identity.__post_init__``).
    """
    live: list[Identity] = []
    for entry in pool[: max(1, max_probes)]:
        if len(live) >= want:
            break
        try:
            response = http_engine.request(method="GET", url=probe_url, headers=dict(entry.headers))
        except Exception as exc:  # scope/transport failure => treat as not live
            logger.debug("token pool: probe for %r failed: %s", entry.name, exc)
            continue
        status = getattr(response, "status_code", None)
        if status == 200:
            live.append(Identity(name=entry.name, headers=dict(entry.headers)))
            logger.info("token pool: %r is live (%s) - %s", entry.name, status, entry.label)
        else:
            logger.info("token pool: %r dropped (status %s) - %s", entry.name, status, entry.label)
    return live
