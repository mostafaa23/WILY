"""Generic OOB interaction paths for REMOTE targets.

Two backends share the OOBCanaryServer interface:
  * the self-hosted canary, now able to bind a reachable interface and
    advertise a public base URL (so a remote target can reach it);
  * :class:`ExternalOOBClient`, a pluggable client that polls a user-supplied
    interactsh-compatible server and records HTTP callbacks as proof.

Neither needs external infrastructure to test: the external client is driven
against an injected poll function / a local mock server.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wily.core.oob_canary import OOBCanaryServer
from wily.core.oob_interaction import ExternalOOBClient

# --------------------------------------------------------------------------
# Self-hosted canary: public_base_url + reachable-interface binding
# --------------------------------------------------------------------------


def test_canary_defaults_to_loopback():
    with OOBCanaryServer() as canary:
        assert canary.is_loopback is True
        assert "127.0.0.1" in canary.base_url


def test_canary_advertises_public_base_url_for_remote_targets():
    # Bind all interfaces but advertise a public address in the forged URLs.
    with OOBCanaryServer(host="0.0.0.0", public_base_url="http://203.0.113.5:8000") as canary:
        assert canary.base_url == "http://203.0.113.5:8000"
        assert canary.is_loopback is False
        token = canary.new_token()
        url = canary.url_for(token, path_suffix="chain.pem")
        assert url == f"http://203.0.113.5:8000/oob/{token}/chain.pem"


def test_canary_public_base_url_trailing_slash_trimmed():
    with OOBCanaryServer(public_base_url="http://example.test:8000/") as canary:
        assert canary.base_url == "http://example.test:8000"


# --------------------------------------------------------------------------
# ExternalOOBClient: records a callback, and falls back cleanly
# --------------------------------------------------------------------------


def test_external_client_requires_a_server_url():
    with pytest.raises(ValueError):
        ExternalOOBClient("")


def test_external_client_builds_callback_urls_under_the_interaction_domain():
    client = ExternalOOBClient(
        "https://poll.example.test", interaction_domain="https://oob.example.test"
    )
    token = client.new_token()
    assert client.url_for(token, "chain.pem") == f"https://oob.example.test/oob/{token}/chain.pem"
    assert client.base_url == "https://oob.example.test"


def test_external_client_records_a_matching_callback():
    recorded: dict[str, list] = {"interactions": []}

    def fake_get(url: str):
        # The server reports whatever interactions it has seen so far.
        return 200, json.dumps(recorded)

    client = ExternalOOBClient(
        "https://poll.example.test", http_get=fake_get, poll_interval=0.05
    )
    token = client.new_token()

    # Simulate the target's HTTP callback landing at the server, carrying the
    # correlation token in its path.
    recorded["interactions"].append(
        {
            "protocol": "http",
            "full-id": f"{token}.oob.example.test",
            "path": f"/oob/{token}/chain.pem",
            "remote-address": "198.51.100.23",
            "headers": {"User-Agent": "victim-server/1.0"},
        }
    )

    hit = client.wait_for_hit(token, timeout=1.0)
    assert hit is not None
    assert hit.method == "HTTP"
    assert hit.remote_addr == "198.51.100.23"
    assert token in hit.path


def test_external_client_ignores_unrelated_interactions():
    def fake_get(url: str):
        return 200, json.dumps(
            [{"protocol": "dns", "full-id": "someone-else.oob.example.test"}]
        )

    client = ExternalOOBClient(
        "https://poll.example.test", http_get=fake_get, poll_interval=0.05
    )
    token = client.new_token()
    assert client.wait_for_hit(token, timeout=0.4) is None


def test_external_client_falls_back_cleanly_when_server_unreachable():
    def boom(url: str):
        raise ConnectionError("server unreachable")

    client = ExternalOOBClient(
        "https://poll.example.test", http_get=boom, poll_interval=0.05
    )
    # No crash, no false positive - just "no hit".
    assert client.wait_for_hit(client.new_token(), timeout=0.3) is None


def test_external_client_handles_non_json_poll_body():
    def html_error(url: str):
        return 200, "<html>not json</html>"

    client = ExternalOOBClient(
        "https://poll.example.test", http_get=html_error, poll_interval=0.05
    )
    assert client.wait_for_hit(client.new_token(), timeout=0.3) is None


def test_external_client_passes_auth_token_in_poll_url():
    seen_urls: list[str] = []

    def capture(url: str):
        seen_urls.append(url)
        return 200, "[]"

    client = ExternalOOBClient(
        "https://poll.example.test",
        auth_token="s3cr3t-poll-key",
        http_get=capture,
        poll_interval=0.05,
    )
    client.wait_for_hit(client.new_token(), timeout=0.2)
    assert seen_urls
    assert "token=s3cr3t-poll-key" in seen_urls[0]


# --------------------------------------------------------------------------
# End-to-end against a local mock interaction server (no external infra)
# --------------------------------------------------------------------------


class _MockInteractionServer:
    """A tiny interactsh-like server: it records any request to /oob/... and
    serves the recorded interactions as JSON at /poll."""

    def __init__(self):
        self.interactions: list[dict] = []
        handler = self._make_handler()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        port = self._httpd.server_address[1]
        return f"http://127.0.0.1:{port}"

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/poll"):
                    body = json.dumps({"interactions": server.interactions}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                # A callback (e.g. the simulated SSRF fetch): record it.
                server.interactions.append(
                    {
                        "protocol": "http",
                        "path": self.path,
                        "full-id": self.path,
                        "remote-address": self.client_address[0],
                        "headers": dict(self.headers.items()),
                    }
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        return Handler

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def test_external_client_end_to_end_against_mock_server():
    import urllib.request

    server = _MockInteractionServer()
    try:
        client = ExternalOOBClient(server.base_url, poll_interval=0.05)
        token = client.new_token()
        callback_url = client.url_for(token, "chain.pem")

        # Simulate the target server fetching the attacker-controlled URL.
        with urllib.request.urlopen(callback_url, timeout=3) as resp:
            resp.read()

        hit = client.wait_for_hit(token, timeout=2.0)
        assert hit is not None
        assert token in hit.path
        assert hit.remote_addr == "127.0.0.1"
    finally:
        server.stop()
