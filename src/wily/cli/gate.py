"""CI gate: turn a scan's findings into a pass/fail decision and exit code.

``wily scan --fail-on LEVEL`` lets Wily sit in a pipeline and stop a build
when it finds something at or above a severity threshold, instead of only
being run by hand. This module holds the pure decision logic (what counts,
what the exit code is) so it can be tested without running a scan.

Two deliberate rules:

  * The threshold is applied to the findings that survive the triage layer.
    A finding an analyst has already marked a false positive via the
    feedback loop (``evidence['feedback_verdict'] == 'false_positive'``) does
    not fail the build - that is the whole point of recording the decision.
  * ``none`` (the default) never fails the build, so adding the flag's
    machinery changes no existing behaviour until a user opts in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from wily.risk.ml.feedback import FALSE_POSITIVE

# Lowest -> highest. A finding fails the gate when its severity rank is at or
# above the chosen threshold's rank.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class FailOn(str, Enum):
    """Severity threshold for ``--fail-on``. ``none`` disables the gate."""

    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _severity_rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get((severity or "").lower(), 0)


def _is_dismissed(finding) -> bool:
    """True when an analyst marked this finding a false positive via the
    feedback loop - such a finding must never fail the build."""
    evidence = getattr(finding, "evidence", None)
    if not isinstance(evidence, dict):
        evidence = finding.get("evidence") if isinstance(finding, dict) else None
    if not isinstance(evidence, dict):
        return False
    return evidence.get("feedback_verdict") == FALSE_POSITIVE


def count_over_threshold(findings: list, fail_on: FailOn | str) -> int:
    """How many findings are at or above ``fail_on``, after excluding ones an
    analyst dismissed as false positives. ``none`` always returns 0."""
    level = FailOn(fail_on) if not isinstance(fail_on, FailOn) else fail_on
    if level is FailOn.none:
        return 0
    threshold = _SEVERITY_RANK[level.value]
    return sum(
        1
        for f in findings
        if _severity_rank(_severity_of(f)) >= threshold
        and not _is_dismissed(f)
    )


def _severity_of(finding) -> str | None:
    if isinstance(finding, dict):
        return finding.get("severity")
    return getattr(finding, "severity", None)


@dataclass
class GateResult:
    """The gate's verdict over one or more domains' findings."""

    fail_on: FailOn
    per_domain: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.per_domain.values())

    @property
    def failing_domains(self) -> list[str]:
        return [d for d, n in self.per_domain.items() if n > 0]

    @property
    def failed(self) -> bool:
        return self.total > 0

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0


def evaluate_gate(results: dict[str, list], fail_on: FailOn | str) -> GateResult:
    """Score each domain's findings against the threshold. ``results`` maps a
    domain label to that domain's post-triage findings."""
    level = FailOn(fail_on) if not isinstance(fail_on, FailOn) else fail_on
    per_domain = {
        domain: count_over_threshold(findings, level)
        for domain, findings in results.items()
    }
    return GateResult(fail_on=level, per_domain=per_domain)


def format_gate_lines(result: GateResult) -> list[str]:
    """Human-readable gate verdict. ``none`` says nothing (the gate is off)."""
    if result.fail_on is FailOn.none:
        return []
    level = result.fail_on.value
    if not result.failed:
        return [f"GATE PASSED: no findings at or above {level}"]
    lines = []
    if len(result.per_domain) > 1:
        for domain in result.failing_domains:
            lines.append(f"  {domain}: {result.per_domain[domain]} at or above {level}")
    return [*lines, f"GATE FAILED: {result.total} finding(s) at or above {level}"]
