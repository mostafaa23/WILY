"""Phase 2 - SSRF header-injection vector (level 4b).

The scanner already probes blind SSRF by putting the canary URL in the URL
*parameter*. These tests cover the new path that instead carries the canary URL
in SSRF-prone request *headers* (``SSRF_INJECTABLE_HEADERS``) and attributes a
returning canary hit to the exact header that fired.

Everything runs against scripted fakes - no real network, no real canary - so
the assertions are deterministic:
  * a canary hit on one header's token yields one finding naming that header,
  * no canary configured (or no hit) yields no header findings,
  * the canary URL is injected into the header, never into the URL parameter,
  * ``Host`` is gated behind ``probe_host_header`` (off by default).
"""

from __future__ import annotations

import uuid

from wily.core.oob_canary import CanaryHit
from wily.core.scope_manager import ScopeManager
from wily.scanners.ssrf_imds import (
    SSRF_INJECTABLE_HEADERS,
    SsrfImdsScanner,
    SsrfImdsTarget,
)


class RecordingEngine:
    """Fake HttpEngine: records every (method, url, headers) and returns an
    empty body, so the param-based IMDS levels all no-op and only the
    header/canary path can produce a finding."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, dict(headers or {})))

        class _Resp:
            text = ""

        return _Resp()


class FakeCanary:
    """Scripted stand-in for OOBCanaryServer / ExternalOOBClient.

    ``fire_header`` (lower-case) names the one header whose probe should report
    a callback; every other token returns no hit. The header name is recovered
    from the path suffix the scanner embeds, proving the scanner binds each
    token to a single header.
    """

    def __init__(self, fire_header: str | None = None) -> None:
        self.fire_header = fire_header.lower() if fire_header else None
        self.base_url = "http://127.0.0.1:0"
        self._suffix_by_token: dict[str, str] = {}

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def url_for(self, token: str, path_suffix: str = "key.json") -> str:
        self._suffix_by_token[token] = path_suffix
        return f"{self.base_url}/oob/{token}/{path_suffix}"

    def wait_for_hit(self, token: str, timeout: float = 5.0) -> CanaryHit | None:
        suffix = self._suffix_by_token.get(token, "")
        # suffix is "ssrf-header/<header-lower>" - match the exact header
        # segment, not a loose substring (so "host" does not match
        # "x-forwarded-host").
        probed_header = suffix.rsplit("/", 1)[-1].lower()
        if self.fire_header and self.fire_header == probed_header:
            return CanaryHit(
                token=token,
                method="GET",
                path=f"/oob/{token}/{suffix}",
                headers={},
                remote_addr="203.0.113.7",
                received_at=0.0,
            )
        return None


def _make_scanner(engine: RecordingEngine) -> SsrfImdsScanner:
    scope = ScopeManager("example.com")
    scanner = SsrfImdsScanner(scope_manager=scope)
    scanner.http = engine
    return scanner


def test_header_hit_is_attributed_to_the_firing_header():
    """A canary hit on the X-Forwarded-Host probe yields exactly one
    header finding, naming that header - not any other in the allowlist."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header="X-Forwarded-Host")
    target = SsrfImdsTarget(
        url="https://example.com/fetch", param_name="url", canary_server=canary
    )

    findings = scanner.run(target)

    header_findings = [f for f in findings if f.category == "cloud-ssrf-blind-header"]
    assert len(header_findings) == 1
    f = header_findings[0]
    assert f.evidence["injected_header"] == "X-Forwarded-Host"
    assert f.evidence["oob_hit_confirmed"] is True
    assert f.evidence["oob_hit_remote_addr"] == "203.0.113.7"
    assert f.asset == "https://example.com/fetch"
    assert f.severity == "high"


def test_canary_url_goes_into_the_header_not_the_url_parameter():
    """The firing header carries the canary URL; the request line for that
    probe must not smuggle the payload into the ?url= parameter."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header="X-Real-IP")
    target = SsrfImdsTarget(
        url="https://example.com/fetch", param_name="url", canary_server=canary
    )

    scanner.run(target)

    header_calls = [c for c in engine.calls if "X-Real-IP" in c[2]]
    assert len(header_calls) == 1
    _method, url, headers = header_calls[0]
    assert headers["X-Real-IP"].startswith("http://127.0.0.1:0/oob/")
    # Payload rode in the header, not the URL parameter.
    assert "url=" not in url
    assert "oob" not in url


def test_no_canary_means_no_header_probes_and_no_findings():
    """Same gating as the param blind probe: without a canary nothing is
    sent on the header path and no header finding is produced."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    target = SsrfImdsTarget(url="https://example.com/fetch", param_name="url")

    findings = scanner.run(target)

    assert [f for f in findings if f.category == "cloud-ssrf-blind-header"] == []
    # No header-injection request was ever sent.
    assert all(
        not any(h in headers for h in SSRF_INJECTABLE_HEADERS)
        for _m, _u, headers in engine.calls
    )


def test_no_canary_hit_means_no_finding():
    """A canary that never reports a callback produces no header finding,
    even though every allowlisted header is probed."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header=None)  # never fires
    target = SsrfImdsTarget(
        url="https://example.com/fetch", param_name="url", canary_server=canary
    )

    findings = scanner.run(target)

    assert [f for f in findings if f.category == "cloud-ssrf-blind-header"] == []


def test_host_header_is_gated_off_by_default():
    """Host can break routing, so it is not probed unless opted in."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header="Host")
    target = SsrfImdsTarget(
        url="https://example.com/fetch", param_name="url", canary_server=canary
    )

    findings = scanner.run(target)

    # Host never probed -> no Host request sent, no Host finding.
    assert all("Host" not in headers for _m, _u, headers in engine.calls)
    assert [f for f in findings if f.category == "cloud-ssrf-blind-header"] == []


def test_host_header_probed_when_opted_in():
    """With probe_host_header=True the Host header is probed and a hit on it
    is attributed to Host."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header="Host")
    target = SsrfImdsTarget(
        url="https://example.com/fetch",
        param_name="url",
        canary_server=canary,
        probe_host_header=True,
    )

    findings = scanner.run(target)

    host_calls = [c for c in engine.calls if "Host" in c[2]]
    assert len(host_calls) == 1
    header_findings = [f for f in findings if f.category == "cloud-ssrf-blind-header"]
    assert len(header_findings) == 1
    assert header_findings[0].evidence["injected_header"] == "Host"


def test_all_forwarding_headers_probed_under_blind():
    """Every non-sensitive allowlisted header gets its own probe (and thus its
    own token) when a canary is configured."""
    engine = RecordingEngine()
    scanner = _make_scanner(engine)
    canary = FakeCanary(fire_header=None)
    target = SsrfImdsTarget(
        url="https://example.com/fetch", param_name="url", canary_server=canary
    )

    scanner.run(target)

    probed_headers = {h for _m, _u, headers in engine.calls for h in headers}
    expected = set(SSRF_INJECTABLE_HEADERS) - {"Host"}
    assert expected.issubset(probed_headers)
    assert "Host" not in probed_headers
