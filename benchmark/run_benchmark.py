"""Measure what Wily's triage layer does to false positives.

Runs AuthzBypassScanner over a target whose ground truth is known
(``vulnerable_benchmark_api.py``) twice:

  * triage OFF - the differential soft-404 baseline disabled, i.e. the
    scanner as a naive "200 with no auth = leak" tool would behave, and
  * triage ON  - the soft-404 baseline enabled.

then scores every finding against the declared ground truth and reports
findings, true positives, false positives and precision for each run. Every
number printed comes from an actual scan of the running app - nothing here
is hard-coded.

    python benchmark/run_benchmark.py

The scoring functions are importable and pure so the numbers are testable
(see tests/test_benchmark_triage.py).
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_BENCH_DIR))
sys.path.insert(0, str(_BENCH_DIR.parent / "src"))

from vulnerable_benchmark_api import (  # noqa: E402
    GROUND_TRUTH,
    SOFT_404_PATH,
    app,
)

from wily.core.scope_manager import ScopeManager  # noqa: E402
from wily.risk.ml.dedup import deduplicate  # noqa: E402
from wily.risk.ml.ranker import rank_findings  # noqa: E402
from wily.scanners.authz_bypass import (  # noqa: E402
    AuthzBypassScanner,
    AuthzBypassTarget,
)

_PORT = 5099
_HOST = "127.0.0.1"


@dataclass
class RunResult:
    """What one scan configuration produced, scored against ground truth."""

    label: str
    findings: int
    true_positives: int
    false_positives: int
    real_vulns_detected: int
    real_vulns_total: int

    @property
    def precision(self) -> float:
        reported = self.true_positives + self.false_positives
        return self.true_positives / reported if reported else 0.0

    @property
    def recall(self) -> float:
        return (
            self.real_vulns_detected / self.real_vulns_total
            if self.real_vulns_total
            else 0.0
        )


def _path_of(asset: str) -> str:
    """The URL path of a finding's asset, so it can be matched to ground truth."""
    return urlparse(asset).path or "/"


def score_run(label: str, findings: list, ground_truth: dict[str, bool]) -> RunResult:
    """Score a run's findings against ground truth. Pure - no I/O.

    A finding is a true positive when it lands on a path ground truth marks
    as a real vulnerability, and a false positive otherwise (a correctly
    protected resource or the generic catch-all). ``real_vulns_detected``
    counts how many of the genuinely vulnerable paths got at least one
    finding, so a drop in false positives that also silenced the real bug
    would be visible rather than hidden.
    """
    true_positives = 0
    false_positives = 0
    detected_real_paths: set[str] = set()
    for finding in findings:
        path = _path_of(getattr(finding, "asset", ""))
        if ground_truth.get(path) is True:
            true_positives += 1
            detected_real_paths.add(path)
        else:
            false_positives += 1

    real_vuln_paths = [p for p, real in ground_truth.items() if real]
    return RunResult(
        label=label,
        findings=len(findings),
        true_positives=true_positives,
        false_positives=false_positives,
        real_vulns_detected=len(detected_real_paths),
        real_vulns_total=len(real_vuln_paths),
    )


def _scan(base_url: str, *, soft_404: bool) -> list:
    """Run the authz scanner over every ground-truth path once, returning
    the combined, de-duplicated, ranked findings - the same post-processing
    a real report goes through."""
    scope = ScopeManager(_HOST, allow_local_targets=True)
    scanner = AuthzBypassScanner(scope_manager=scope, confirm_destructive=True)
    probe_url = f"{base_url}{SOFT_404_PATH}" if soft_404 else None

    findings: list = []
    for path in GROUND_TRUTH:
        target = AuthzBypassTarget(
            url=f"{base_url}{path}",
            # GET only: a data leak is a response that returns a body, and the
            # differential baseline compares bodies. HEAD returns a 200 with no
            # body, so it can neither leak data nor be compared to the baseline;
            # testing it would just add a body-less finding the filter cannot
            # reason about. See benchmark/README.md ("Honest limitations").
            methods_to_test=["GET"],
            include_destructive_methods=True,
            soft_404_probe_url=probe_url,
        )
        findings += scanner.run(target)

    return rank_findings(deduplicate(findings))


def run_benchmark(base_url: str) -> tuple[RunResult, RunResult]:
    """Scan twice (triage off, then on) and score both runs."""
    off = score_run("triage OFF (naive 200=leak)", _scan(base_url, soft_404=False), GROUND_TRUTH)
    on = score_run("triage ON  (soft-404 baseline)", _scan(base_url, soft_404=True), GROUND_TRUTH)
    return off, on


def _format_table(off: RunResult, on: RunResult) -> str:
    rows = [
        ("", off.label, on.label),
        ("findings", off.findings, on.findings),
        ("true positives", off.true_positives, on.true_positives),
        ("false positives", off.false_positives, on.false_positives),
        ("precision", f"{off.precision:.2f}", f"{on.precision:.2f}"),
        (
            "real vulns found",
            f"{off.real_vulns_detected}/{off.real_vulns_total}",
            f"{on.real_vulns_detected}/{on.real_vulns_total}",
        ),
    ]
    w0 = max(len(str(r[0])) for r in rows)
    w1 = max(len(str(r[1])) for r in rows)
    w2 = max(len(str(r[2])) for r in rows)
    lines = []
    for i, (a, b, c) in enumerate(rows):
        lines.append(f"  {a!s:<{w0}}  {b!s:<{w1}}  {c!s:<{w2}}")
        if i == 0:
            lines.append(f"  {'-' * w0}  {'-' * w1}  {'-' * w2}")
    return "\n".join(lines)


def _start_server() -> threading.Thread:
    thread = threading.Thread(
        target=lambda: app.run(host=_HOST, port=_PORT, use_reloader=False),
        daemon=True,
    )
    thread.start()
    time.sleep(1.5)
    return thread


def main() -> None:  # pragma: no cover - exercised via the test, not in CI headless
    _start_server()
    base_url = f"http://{_HOST}:{_PORT}"
    off, on = run_benchmark(base_url)

    print("=" * 64)
    print("Wily triage benchmark - false positives on a known target")
    print("=" * 64)
    print(_format_table(off, on))
    print()
    removed = off.false_positives - on.false_positives
    print(
        f"  -> {removed} false positive(s) removed, "
        f"precision {off.precision:.2f} -> {on.precision:.2f}, "
        f"real vulnerabilities still detected: {on.real_vulns_detected}/{on.real_vulns_total}"
    )

    results_path = _BENCH_DIR / "results.json"
    results_path.write_text(
        json.dumps(
            {
                "triage_off": off.__dict__ | {"precision": off.precision, "recall": off.recall},
                "triage_on": on.__dict__ | {"precision": on.precision, "recall": on.recall},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\n  results written to {results_path}")


if __name__ == "__main__":
    main()
