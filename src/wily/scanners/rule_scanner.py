"""Generic runner for declarative YAML rules (templates/rules/**/*.yaml).

Given one HTTP-endpoint asset, it runs every loaded rule whose ``asset-type``
matches, performs the rule's declared request through the shared, scope- and
safety-enforcing :class:`HttpEngine`, evaluates the matchers, and emits a
:class:`Finding` on a match.

Safety (the project's read-only stance) is enforced here, not trusted to the
rule file:

  * Only idempotent, non-mutating methods (GET/HEAD/OPTIONS) are ever sent.
    A rule asking for POST/PUT/DELETE/PATCH is skipped.
  * ``authorization.mode: destructive`` rules are always skipped.
  * ``authorization.requires_owned_infra`` rules run only when the caller
    passes ``confirm_owned_infra=True`` (the same gate ssrf_imds uses).
  * ``dsl`` matchers (which need an external piece such as an out-of-band
    callback) are skipped with a recorded reason, never silently "matched".

Matched evidence is passed through ``sanitize_text`` so a secret-exposure
rule can never write a raw credential into a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.evidence.sanitize import sanitize_text
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine
from wily.templates.matcher import (
    UnsupportedMatcherError,
    build_context,
    evaluate,
    has_unresolved_placeholders,
    interpolate,
)
from wily.templates.schema import AuthorizationMode, Severity, Template

# Methods the generic runner is allowed to send. Everything else is a
# state-changing verb and is refused regardless of what a rule declares.
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Default confidence per severity for a rule match (rules don't carry an
# explicit confidence; a declarative word/regex/status hit is treated as a
# fairly strong but not perfect signal).
_SEVERITY_CONFIDENCE = {
    Severity.CRITICAL.value: 0.9,
    Severity.HIGH.value: 0.85,
    Severity.MEDIUM.value: 0.75,
    Severity.LOW.value: 0.6,
    Severity.INFO.value: 0.4,
}


@dataclass
class RuleScanTarget:
    """One asset to run rules against. ``asset_type`` must equal the rule's
    ``asset-type`` for a rule to apply (default: a plain HTTP endpoint)."""

    url: str
    asset_type: str = "http-endpoint"
    # Extra interpolation variables for this asset (e.g. a discovered param
    # name, or a CANARY_URL once out-of-band infra exists).
    extra_variables: dict[str, str] = field(default_factory=dict)


@dataclass
class SkippedRule:
    """A rule that did not run, and why - surfaced so a scan can explain
    coverage gaps instead of silently dropping checks."""

    rule_id: str
    reason: str


class RuleScanner(BaseScanner):
    name = "rule_scanner"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self,
        rules: list[Template],
        scope_manager: ScopeManager,
        http_engine: HttpEngine | None = None,
        confirm_owned_infra: bool = False,
    ) -> None:
        self.rules = rules
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)
        self._confirm_owned_infra = confirm_owned_infra
        # Populated by run(); lets the caller report why rules were skipped.
        self.skipped: list[SkippedRule] = []

    def _applicable(self, rule: Template, target: RuleScanTarget) -> str | None:
        """Return a skip reason if this rule should not run against ``target``,
        else ``None``."""
        if rule.asset_type != target.asset_type:
            return f"asset-type {rule.asset_type!r} != target {target.asset_type!r}"
        if rule.authorization.mode == AuthorizationMode.DESTRUCTIVE:
            return "authorization.mode is destructive (never run in an ordinary scan)"
        if rule.authorization.requires_owned_infra and not self._confirm_owned_infra:
            return "requires_owned_infra but confirm_owned_infra was not given"
        methods = {req.method.upper() for req in rule.request}
        unsafe = methods - _READ_ONLY_METHODS
        if unsafe:
            return f"declares non-read-only method(s) {sorted(unsafe)}"
        return None

    def run(self, target: RuleScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        self.skipped = []

        for rule in self.rules:
            skip = self._applicable(rule, target)
            if skip:
                self.skipped.append(SkippedRule(rule.id, skip))
                continue

            variables = {**rule.variables, **target.extra_variables}
            try:
                finding = self._run_one(rule, target, variables)
            except UnsupportedMatcherError as exc:
                self.skipped.append(SkippedRule(rule.id, str(exc)))
                continue
            except Exception as exc:  # a single bad rule never aborts the asset
                self.skipped.append(SkippedRule(rule.id, f"error: {exc}"))
                continue
            if finding is not None:
                findings.append(finding)

        return findings

    def _run_one(
        self, rule: Template, target: RuleScanTarget, variables: dict[str, str]
    ) -> Finding | None:
        context = build_context(target.url, variables)

        # Only the first request is evaluated by this minimal runner; multi-step
        # request chains are a future extension. Rules here declare one request.
        req = rule.request[0]
        url = interpolate(req.path, context)
        if has_unresolved_placeholders(url, context):
            raise UnsupportedMatcherError(
                f"request path has unresolved placeholder(s): {req.path!r} "
                "(needs a variable the runner cannot supply, e.g. a canary URL)"
            )
        headers = {
            k: interpolate(v, context) for k, v in (req.headers or {}).items()
        }
        body = interpolate(req.body, context) if req.body else None

        response = self.http.request(
            method=req.method.upper(), url=url, headers=headers or None, body=body
        )

        matched, match_evidence = evaluate(rule, response, context)
        if not matched:
            return None

        confidence = _SEVERITY_CONFIDENCE.get(rule.info.severity.value, 0.7)
        evidence = {
            "rule_id": rule.id,
            "rule_name": rule.info.name,
            # Dedup identity shared with a code-scanner twin (risk/rules_engine
            # keys on evidence["technique"]); falls back to the rule id so a
            # standalone rule never collapses with an unrelated finding.
            "technique": rule.dedup_technique or rule.id,
            "source": "yaml-template",
            "request_method": req.method.upper(),
            "request_url": url,
            "response_status": response.status_code,
            "matchers": [_sanitize_fragment(frag) for frag in match_evidence],
        }
        return Finding(
            asset=target.url,
            category=rule.info.category,
            severity=rule.info.severity.value,
            confidence=confidence,
            discovery_source="template-rule",
            evidence=evidence,
            remediation=rule.remediation,
        )


def _sanitize_fragment(fragment: dict) -> dict:
    """Redact any secret the matcher captured (matched regex/word spans) before
    it reaches a finding, so a secret-exposure rule stores only a safe
    indicator, never the raw credential."""
    safe = dict(fragment)
    for key in ("matches", "matched_words"):
        if key in safe and isinstance(safe[key], list):
            safe[key] = [sanitize_text(str(item)) for item in safe[key]]
    return safe
