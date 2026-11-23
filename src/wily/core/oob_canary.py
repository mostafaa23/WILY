"""Out-of-band (OOB) canary server.

A lightweight local HTTP server that logs every request it receives, so a
scanner can prove a target actually sent an outbound request (jku fetch,
SSRF, ...) rather than relying only on the target's own HTTP response.

By default it binds loopback (127.0.0.1), which only a *local* target can
reach. To confirm blind SSRF / jku / x5u against a *remote* target, bind a
reachable interface (``host="0.0.0.0"``) and advertise the externally
reachable address with ``public_base_url`` (e.g. a public IP or a
port-forwarded host) - the forged URLs then point at that public address
while the listener still records every callback locally. For a hosted
interaction service instead, see
:class:`wily.core.oob_interaction.ExternalOOBClient`, which speaks to a
user-supplied interactsh-compatible server behind the same
``new_token``/``url_for``/``wait_for_hit`` interface.

Use as a context manager (``with OOBCanaryServer() as canary:``) so
``stop()`` always runs; runs on its own background thread, independent of
any asyncio event loop.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self


@dataclass
class CanaryHit:
    token: str
    method: str
    path: str
    headers: dict
    remote_addr: str
    received_at: float


class OOBCanaryServer:
    """A single canary server instance can serve several different tokens
    at the same time - each test (each candidate finding) gets a unique
    token, so results from different tests running concurrently never mix."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        public_base_url: str | None = None,
    ) -> None:
        """``host``/``port`` are what the listener binds. ``public_base_url``,
        when given, is the externally reachable base URL advertised in the
        forged URLs (``http://PUBLIC_IP:PORT``) - set it when binding a
        non-loopback interface so a remote target can actually reach the
        canary. The trailing slash is trimmed; the bound port still wins if
        the public URL omits one."""
        self._hits: dict[str, list[CanaryHit]] = {}
        self._lock = threading.Lock()
        handler = self._make_handler()
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self._stopped = False
        self._public_base_url = public_base_url.rstrip("/") if public_base_url else None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        # An explicit public base URL (for remote targets) always wins over the
        # bound address, so the forged URLs point somewhere the target can reach.
        if self._public_base_url:
            return self._public_base_url
        host, port = self._httpd.server_address[:2]
        display_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
        return f"http://{display_host}:{port}"

    @property
    def is_loopback(self) -> bool:
        """True when the advertised address is loopback (reachable only by a
        local target). A remote-target run should not advertise a loopback
        canary - callers use this to warn/skip accordingly."""
        from urllib.parse import urlsplit

        host = urlsplit(self.base_url).hostname or ""
        return host in ("127.0.0.1", "::1", "localhost")

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def url_for(self, token: str, path_suffix: str = "key.json") -> str:
        return f"{self.base_url}/oob/{token}/{path_suffix}"

    def record_hit(self, hit: CanaryHit) -> None:
        with self._lock:
            self._hits.setdefault(hit.token, []).append(hit)

    def wait_for_hit(self, token: str, timeout: float = 5.0) -> CanaryHit | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                hits = self._hits.get(token)
            if hits:
                return hits[0]
            time.sleep(0.1)
        return None

    def all_hits(self, token: str) -> list[CanaryHit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                parts = self.path.strip("/").split("/")
                token = parts[1] if len(parts) >= 2 and parts[0] == "oob" else self.path

                server.record_hit(
                    CanaryHit(
                        token=token,
                        method=self.command,
                        path=self.path,
                        headers=dict(self.headers.items()),
                        remote_addr=self.client_address[0],
                        received_at=time.time(),
                    )
                )

                body = b'{"keys":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def log_message(self, format, *args):
                pass

        return Handler

    def stop(self) -> None:
        """Safe to call more than once (idempotent)."""
        if self._stopped:
            return
        self._stopped = True
        self._httpd.shutdown()
        self._httpd.server_close()
