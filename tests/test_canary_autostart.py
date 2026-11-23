"""SSRF OOB canary auto-start decision + graceful bind-failure fallback.

The canary now starts automatically (no --blind needed) when SSRF is enabled,
and must fall back exactly to the old behavior - no canary, no crash - if the
local listener cannot bind.
"""

from __future__ import annotations

import pytest

from wily.cli.commands import scan_all
from wily.core.oob_canary import OOBCanaryServer


@pytest.mark.parametrize(
    ("blind", "auto_canary", "confirm_owned_infra", "expected"),
    [
        # Plain `wily scan`: auto-canary on, SSRF on -> canary auto-starts.
        (False, True, True, True),
        # --no-auto-canary opts out of the automatic start.
        (False, False, True, False),
        # SSRF disabled (--no-owned-infra): no point starting the canary.
        (False, True, False, False),
        # --blind forces it on even with --no-auto-canary / SSRF-gated off.
        (True, False, False, True),
        (True, True, False, True),
    ],
)
def test_want_canary_decision(blind, auto_canary, confirm_owned_infra, expected):
    assert (
        scan_all._want_canary(
            blind=blind, auto_canary=auto_canary, confirm_owned_infra=confirm_owned_infra
        )
        is expected
    )


def test_start_oob_canary_success():
    canary, error = scan_all._start_oob_canary()
    try:
        assert error is None
        assert canary is not None
        assert canary.base_url.startswith("http://127.0.0.1:")
    finally:
        if canary is not None:
            canary.stop()


def test_start_oob_canary_bind_failure_falls_back(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise OSError("address already in use")

    monkeypatch.setattr(scan_all, "OOBCanaryServer", _boom)
    canary, error = scan_all._start_oob_canary()
    assert canary is None
    assert isinstance(error, OSError)


def test_oob_canary_is_loopback_only():
    # The auto-started canary binds loopback - a remote target can't reach it,
    # so auto-start yields real evidence only against local/owned infra.
    canary = OOBCanaryServer()
    try:
        assert "127.0.0.1" in canary.base_url
    finally:
        canary.stop()
