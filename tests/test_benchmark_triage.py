"""Tests for the triage benchmark (benchmark/).

Two layers:
  * pure unit tests for the scoring logic that turns findings into the
    reported precision/recall numbers - fast, no server, and
  * one integration test that starts the benchmark target and runs the real
    scan both ways, guarding the headline claim (the triage layer drops
    false positives without dropping the real vulnerability).
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

_BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(_BENCH_DIR))

from run_benchmark import _path_of, run_benchmark, score_run  # noqa: E402


@dataclass
class _FakeFinding:
    asset: str


_GT = {"/orders/1": True, "/public/catalog": False, "/account": False}


def test_path_of_extracts_path_from_url():
    assert _path_of("http://h:5099/orders/1?q=1") == "/orders/1"
    assert _path_of("http://h:5099") == "/"


def test_score_run_counts_true_and_false_positives():
    findings = [
        _FakeFinding("http://h/orders/1"),      # TP
        _FakeFinding("http://h/public/catalog"),  # FP
        _FakeFinding("http://h/account"),         # FP
    ]
    result = score_run("x", findings, _GT)
    assert result.true_positives == 1
    assert result.false_positives == 2
    assert result.precision == pytest.approx(1 / 3)
    assert result.real_vulns_total == 1
    assert result.real_vulns_detected == 1
    assert result.recall == pytest.approx(1.0)


def test_score_run_perfect_precision_when_only_real_vuln_reported():
    result = score_run("x", [_FakeFinding("http://h/orders/1")], _GT)
    assert result.false_positives == 0
    assert result.precision == pytest.approx(1.0)
    assert result.recall == pytest.approx(1.0)


def test_score_run_detects_lost_recall():
    # No findings at all: precision is 0 (nothing reported) AND recall is 0,
    # so a filter that silenced the real bug cannot hide behind "0 FPs".
    result = score_run("x", [], _GT)
    assert result.precision == 0.0
    assert result.recall == 0.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def test_triage_layer_removes_false_positives_without_losing_the_real_bug():
    """End-to-end: the soft-404 differential baseline must cut false
    positives while still detecting the one genuine vulnerability."""
    from vulnerable_benchmark_api import app

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    ).start()
    if not _wait_until_up(base_url + "/", timeout=5.0):
        pytest.skip("benchmark target did not start in time")

    off, on = run_benchmark(base_url)

    # The real bug is found both ways - triage must not silence it.
    assert off.real_vulns_detected == off.real_vulns_total
    assert on.real_vulns_detected == on.real_vulns_total

    # Triage strictly reduces false positives and strictly improves precision.
    assert on.false_positives < off.false_positives
    assert on.precision > off.precision
    # On this target the catch-all FPs are fully removed.
    assert on.false_positives == 0
    assert on.precision == pytest.approx(1.0)
