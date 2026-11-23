"""Pluggable out-of-band interaction client for *remote* targets.

:class:`wily.core.oob_canary.OOBCanaryServer` is a listener Wily stands up
itself; it only yields evidence when the target can reach it (loopback by
default, or a bound public interface). The alternative, used when you cannot
expose a listener but already run an interaction service, is to register with
that service and poll it for callbacks. :class:`ExternalOOBClient` is that
path: a thin, opt-in client that speaks to a **user-supplied**,
interactsh-compatible correlation server over plain HTTP.

It deliberately ships **no default server** - the endpoint is always supplied
by the user (``--oob-server``). It exposes the exact same
``new_token`` / ``url_for`` / ``wait_for_hit`` interface the scanners already
use for the local canary, so blind SSRF, jku and x5u confirm remote
interactions with no change to their own code.

Scope of this reimplementation (detection only, from the interactsh *idea*):
  * Correlation is by an opaque per-test token embedded in the callback URL's
    path, matched against the interactions the server reports.
  * The poll is a simple authenticated-GET-returns-JSON contract (documented
    on :class:`ExternalOOBClient`). The full interactsh wire protocol (RSA
    registration + AES-GCM encrypted poll) is intentionally out of scope; a
    deployment needing it should point ``http_get`` at a small adapter.
  * Every network error falls back cleanly to "no hit" (``wait_for_hit``
    returns ``None``) - a confirmation is only ever reported on a real,
    parsed callback, never inferred from a failure.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from typing import Self

from wily.core.oob_canary import CanaryHit

__all__ = ["ExternalOOBClient"]

# Interaction fields we scan for the correlation token, in priority order. A
# tolerant union so one client works across interactsh-compatible servers that
# label the same thing differently.
_TOKEN_FIELDS = ("full-id", "full_id", "unique-id", "unique_id", "q", "path", "url", "raw")
_METHOD_FIELDS = ("protocol", "method", "type")
_REMOTE_FIELDS = ("remote-address", "remote_address", "remote-addr", "remote_addr", "client")


def _default_http_get(timeout: float) -> Callable[[str], tuple[int, str]]:
    """A minimal GET returning ``(status, text)``. Uses urllib directly (not
    the scope-enforcing HttpEngine) because the OOB server is the user's own
    infrastructure, deliberately outside the target's scope."""

    def _get(url: str) -> tuple[int, str]:
        from urllib.request import Request, urlopen

        req = Request(url, headers={"User-Agent": "wily-oob-client/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body

    return _get


class ExternalOOBClient:
    """Client for a user-supplied interactsh-compatible interaction server.

    Parameters
    ----------
    server_url:
        Base URL of the interaction server to **poll** for recorded callbacks
        (e.g. ``https://oob.example.com``).
    interaction_domain:
        Base URL the forged callback URLs should target. Defaults to
        ``server_url``; set it when the reachable callback domain differs from
        the poll host (interactsh hands out a per-session subdomain).
    poll_path:
        Path GET-ed to list interactions (default ``/poll``).
    auth_token:
        Optional token added to the poll request as ``?token=`` (many
        self-hosted interaction servers gate polling behind one).
    http_get:
        Injectable ``(url) -> (status, text)`` for testing / custom transports.
    poll_interval, timeout:
        Poll cadence and per-request timeout, both in seconds.

    The poll response may be a JSON list of interaction objects, or an object
    with an ``interactions``/``data`` list. Each interaction is matched to a
    test by whether the test's token appears in any of its id/path/url fields.
    """

    def __init__(
        self,
        server_url: str,
        *,
        interaction_domain: str | None = None,
        poll_path: str = "/poll",
        auth_token: str | None = None,
        http_get: Callable[[str], tuple[int, str]] | None = None,
        poll_interval: float = 0.5,
        timeout: float = 5.0,
    ) -> None:
        if not server_url or not str(server_url).strip():
            raise ValueError("ExternalOOBClient requires a non-empty server_url")
        self._server_url = server_url.rstrip("/")
        self._interaction_domain = (interaction_domain or server_url).rstrip("/")
        self._poll_path = "/" + poll_path.lstrip("/")
        self._auth_token = auth_token
        self._http_get = http_get or _default_http_get(timeout)
        self._poll_interval = max(0.05, poll_interval)
        self._timeout = timeout

    @property
    def base_url(self) -> str:
        return self._interaction_domain

    @property
    def is_loopback(self) -> bool:
        from urllib.parse import urlsplit

        host = urlsplit(self._interaction_domain).hostname or ""
        return host in ("127.0.0.1", "::1", "localhost")

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def url_for(self, token: str, path_suffix: str = "key.json") -> str:
        return f"{self._interaction_domain}/oob/{token}/{path_suffix}"

    def _poll_url(self) -> str:
        if self._auth_token:
            sep = "&" if "?" in self._poll_path else "?"
            return f"{self._server_url}{self._poll_path}{sep}token={self._auth_token}"
        return f"{self._server_url}{self._poll_path}"

    def _parse_interactions(self, text: str) -> list[dict]:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("interactions") or data.get("data") or []
        else:
            items = []
        return [it for it in items if isinstance(it, dict)]

    def _match(self, interaction: dict, token: str) -> CanaryHit | None:
        hit_field = None
        for field in _TOKEN_FIELDS:
            value = interaction.get(field)
            if isinstance(value, str) and token in value:
                hit_field = value
                break
        if hit_field is None:
            return None

        method = "GET"
        for field in _METHOD_FIELDS:
            value = interaction.get(field)
            if isinstance(value, str) and value:
                method = value.upper()
                break

        remote = ""
        for field in _REMOTE_FIELDS:
            value = interaction.get(field)
            if isinstance(value, str) and value:
                remote = value
                break

        headers = interaction.get("headers")
        if not isinstance(headers, dict):
            headers = {}

        return CanaryHit(
            token=token,
            method=method,
            path=str(interaction.get("path") or interaction.get("url") or hit_field),
            headers=headers,
            remote_addr=remote,
            received_at=time.time(),
        )

    def wait_for_hit(self, token: str, timeout: float = 5.0) -> CanaryHit | None:
        """Poll the interaction server until a callback referencing ``token``
        appears, or ``timeout`` elapses. Any transport/parse error is swallowed
        and treated as "no interaction yet" - a hit is reported only for a real,
        parsed callback, never inferred from an error."""
        deadline = time.time() + timeout
        url = self._poll_url()
        while time.time() < deadline:
            try:
                status, text = self._http_get(url)
            except Exception:
                status, text = 0, ""
            if status and 200 <= status < 300:
                for interaction in self._parse_interactions(text):
                    hit = self._match(interaction, token)
                    if hit is not None:
                        return hit
            time.sleep(self._poll_interval)
        return None

    def stop(self) -> None:
        """No persistent listener to tear down (the server is external). Present
        so the client is drop-in interchangeable with ``OOBCanaryServer``."""
        return None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
