"""Evaluate a rule's declarative matchers against an HTTP response.

This is intentionally small: status / word / regex matching plus simple
``{{variable}}`` interpolation. It is NOT a general expression engine - the
``dsl`` matcher type is reported as unsupported (it needs an external piece,
such as an out-of-band interaction callback, that the generic HTTP runner
cannot provide; see rules/ssrf/imds-ssrf-candidate.yaml).

No ``eval``/``exec`` anywhere: matching is pure substring/regex/comparison,
so a malicious or malformed rule can never run code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from wily.templates.schema import (
    MatcherCondition,
    MatcherPart,
    MatcherType,
    RuleMatcher,
    Template,
)

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


class UnsupportedMatcherError(RuntimeError):
    """Raised when a matcher cannot be evaluated by the generic runner
    (e.g. a ``dsl`` matcher that depends on an external callback result)."""


def build_context(url: str, variables: dict[str, str] | None = None) -> dict[str, str]:
    """The interpolation context for a request against ``url``.

    Built-ins: ``BaseURL`` (the full URL), ``Hostname`` (host[:port]),
    ``Host`` (host only). Rule ``variables`` are layered on top and win over
    built-ins if they collide.
    """
    split = urlsplit(url)
    host = split.hostname or ""
    hostport = split.netloc or host
    ctx: dict[str, str] = {
        "BaseURL": url,
        "RootURL": f"{split.scheme}://{hostport}" if split.scheme else url,
        "Hostname": hostport,
        "Host": host,
    }
    if variables:
        ctx.update({k: str(v) for k, v in variables.items()})
    return ctx


def interpolate(value: str, context: dict[str, str]) -> str:
    """Replace every ``{{name}}`` in ``value`` from ``context``.

    An unknown placeholder is left untouched and signalled via
    :func:`has_unresolved_placeholders`, so the runner can skip a rule whose
    request still references something it cannot supply (e.g. ``{{CANARY_URL}}``).
    """
    return _PLACEHOLDER_RE.sub(
        lambda m: context.get(m.group(1), m.group(0)), value
    )


def has_unresolved_placeholders(value: str, context: dict[str, str]) -> bool:
    return any(
        m.group(1) not in context for m in _PLACEHOLDER_RE.finditer(value)
    )


def _serialize_headers(headers: dict) -> str:
    """One ``Name: value`` per line, so a ``part: header`` word/regex matcher
    can look for a reflected value the same way a human reads response headers."""
    return "\n".join(f"{name}: {value}" for name, value in headers.items())


@dataclass
class _Response:
    """The minimal view of an HTTP response a matcher needs. Mirrors the
    ``HttpResponse`` fields used here, so tests can pass a light stand-in."""

    status_code: int
    headers: dict
    text: str


def _part_text(response, part: str) -> str:
    if part == MatcherPart.HEADER.value:
        return _serialize_headers(getattr(response, "headers", {}) or {})
    # body is the default; status is handled by the status matcher itself.
    return getattr(response, "text", "") or ""


def _eval_single(
    matcher: RuleMatcher, response, context: dict[str, str]
) -> tuple[bool, dict]:
    """Evaluate one matcher. Returns (matched, evidence-fragment).

    ``negative`` inversion is applied by the caller, not here, so the evidence
    fragment always describes what was actually observed.
    """
    mtype = matcher.type
    condition = matcher.condition

    if mtype == MatcherType.DSL.value:
        raise UnsupportedMatcherError(
            "dsl matcher requires an external evaluation the generic rule "
            "runner does not provide (e.g. an out-of-band callback result)"
        )

    if mtype == MatcherType.STATUS.value:
        codes = matcher.status or []
        matched = getattr(response, "status_code", None) in codes
        return matched, {"type": "status", "expected": codes,
                         "observed": getattr(response, "status_code", None)}

    if mtype == MatcherType.WORD.value:
        haystack = _part_text(response, matcher.part).lower()
        words = [interpolate(w, context).lower() for w in (matcher.words or [])]
        hits = [w for w in words if w in haystack]
        matched = (
            bool(words)
            and (len(hits) == len(words) if condition == MatcherCondition.AND.value
                 else bool(hits))
        )
        return matched, {"type": "word", "part": matcher.part,
                         "condition": condition, "matched_words": hits}

    if mtype == MatcherType.REGEX.value:
        haystack = _part_text(response, matcher.part)
        patterns = [interpolate(r, context) for r in (matcher.regex or [])]
        found: list[str] = []
        per_pattern_hit: list[bool] = []
        for pat in patterns:
            try:
                compiled = re.compile(pat)
            except re.error:
                per_pattern_hit.append(False)
                continue
            m = compiled.search(haystack)
            per_pattern_hit.append(m is not None)
            if m:
                found.append(m.group(0))
        matched = (
            bool(patterns)
            and (all(per_pattern_hit) if condition == MatcherCondition.AND.value
                 else any(per_pattern_hit))
        )
        return matched, {"type": "regex", "part": matcher.part,
                         "condition": condition, "matches": found}

    raise UnsupportedMatcherError(f"unknown matcher type: {mtype!r}")


def evaluate(
    template: Template, response, context: dict[str, str]
) -> tuple[bool, list[dict]]:
    """Evaluate all of ``template``'s matchers against ``response``.

    Returns ``(matched, evidence)`` where ``matched`` honours the template's
    ``matchers-condition`` (and/or). Raises :class:`UnsupportedMatcherError`
    if any matcher cannot be evaluated here, so the runner can skip the whole
    rule with a clear reason rather than reporting a half-evaluated result.
    """
    results: list[bool] = []
    evidence: list[dict] = []
    for matcher in template.matchers:
        matched, frag = _eval_single(matcher, response, context)
        if matcher.negative:
            matched = not matched
            frag["negated"] = True
        results.append(matched)
        evidence.append(frag)

    if template.matchers_condition == MatcherCondition.OR.value:
        overall = any(results)
    else:
        overall = all(results) if results else False
    return overall, evidence
