"""IAM / ARN clue extractor (black-box recon).

Surfaces AWS IAM *identifiers* that leak in black-box recon - ARNs, IAM role
names, ``AssumeRole`` snippets, and AWS account ids - without any live AWS
credentials. These are hints that map a target's AWS footprint, not live
secrets: ``scanners/secret_scan.py`` already handles leaked credentials, and
this module is deliberately its low-severity sibling.

It runs over the same corpus the secret scan sees (discovered JS bundles,
response bodies, imported Burp/HAR traffic) plus any accidentally-exposed IaC
files discovery turns up (``.tf``, ``serverless.yml``,
``cloudformation.{yml,json}``, ``policy.json``). Detection only: no AWS API is
ever called, and account ids are masked in the stored evidence.

Findings are ``iam-clue-*`` and informational/low by default. The trigger layer
(``risk/triggers.py``) escalates them to an ``iam_privesc`` follow-up only when
the tester supplied ``--iam-file``, so a leaked identifier is corroborated
against real authorization details rather than reported as a vuln on its own.

Takes pre-fetched text via ``sources`` (fully offline, unit-testable) and/or
``fetch_urls`` for in-scope URLs it fetches itself through the shared
HttpEngine, mirroring ``secret_scan.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.evidence.sanitize import sanitize_text
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

# How much context around a match is kept (after redaction) for the analyst to
# locate the clue in the source, without dumping the whole file.
_CONTEXT_WINDOW = 48

# Path suffixes of accidentally-exposed Infrastructure-as-Code files worth
# parsing read-only when discovery finds them. Matched case-insensitively
# against a URL/file path (see ``looks_like_iac``).
IAC_FILE_SUFFIXES: tuple[str, ...] = (
    ".tf",
    ".tfvars",
    "serverless.yml",
    "serverless.yaml",
    "cloudformation.yml",
    "cloudformation.yaml",
    "cloudformation.json",
    "policy.json",
    "template.yml",
    "template.yaml",
)


def looks_like_iac(location: str) -> bool:
    """True when ``location`` (a URL or file path) names an IaC file we parse."""
    if not location:
        return False
    path = location.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(IAC_FILE_SUFFIXES)


# --- Clue detectors --------------------------------------------------------
#
# Each distinctive AWS identifier shape. These describe *identifiers*, not
# credential values, so the regexes are anchored on structure (ARN grammar) or
# an explicit label (``RoleName:``) to stay low-noise - a bare 12-digit number
# or a lone word is never treated as a clue on its own.

# arn:<partition>:<service>:<region>:<account>:<resource>
# region and account are optional (empty for e.g. ``arn:aws:s3:::bucket/key``).
_ARN_RE = re.compile(
    r"arn:(?P<partition>aws[a-z0-9\-]*)"
    r":(?P<service>[a-z0-9\-]{2,40})"
    r":(?P<region>[a-z0-9\-]*)"
    r":(?P<account>\d{0,12})"
    r":(?P<resource>[A-Za-z0-9\-_./:*@+=]+)"
)

# sts:AssumeRole / AssumeRoleWithWebIdentity / AssumeRoleWithSAML as an action
# (``sts:AssumeRole``) or SDK call (``assumeRole``) - an explicit assume-role
# intent, not just any mention of a role. Case-insensitive so both the IAM
# action spelling and the camelCase SDK call are caught; the word is
# distinctive enough that this stays low-noise.
_ASSUME_ROLE_RE = re.compile(
    r"\b(?:sts:)?AssumeRole(?:WithWebIdentity|WithSAML)?\b", re.IGNORECASE
)

# A role name behind an explicit label: "RoleName": "x", iam_role_name=x, etc.
# IAM role names are <= 64 chars from [\w+=,.@-].
_ROLE_NAME_RE = re.compile(
    r"(?i)[\"']?(?:iam[_-]?)?role[_-]?name[\"']?\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9+=,.@_\-]{1,64})"
)

# A 12-digit AWS account id behind an explicit label (bare 12-digit numbers are
# far too noisy to treat as account ids on their own).
_ACCOUNT_ID_RE = re.compile(
    r"(?i)[\"']?(?:aws[_-]?)?account[_-]?id[\"']?\s*[:=]\s*[\"']?(\d{12})\b"
)

# Any 12-digit run (an account id embedded in an ARN or sitting unlabelled
# nearby), masked out of the stored context snippet so a raw account id never
# leaks through a neighbouring clue's evidence.
_ACCOUNT_IN_TEXT_RE = re.compile(r"\b\d{12}\b")

# Per-kind risk. Everything here is an identifier, not a live secret, so it
# stays informational/low; the trigger layer is what escalates it when an IAM
# file is available to corroborate it.
_KIND_SEVERITY: dict[str, str] = {
    "arn": "info",
    "assume-role": "low",
    "role-name": "info",
    "account-id": "info",
}
_KIND_CONFIDENCE: dict[str, float] = {
    "arn": 0.9,
    "assume-role": 0.5,
    "role-name": 0.6,
    "account-id": 0.7,
}
# ARNs that name IAM/STS identities are the most actionable clues (they point
# straight at a role/user/policy), so bump them from info to low.
_IAM_SERVICES = frozenset({"iam", "sts"})

_REMEDIATION = (
    "Avoid exposing AWS resource identifiers (ARNs, IAM role names, account "
    "ids) in frontend bundles, API/error responses, or published IaC files - "
    "they let an attacker map your AWS footprint and target specific IAM "
    "principals. Serve configuration without embedding infrastructure "
    "identifiers, keep IaC out of the web root, and review the referenced "
    "principals for least privilege."
)


@dataclass
class IamClueSource:
    """One named text blob to scan. ``location`` is where it came from (a URL,
    a file name, "imported-traffic") - recorded in evidence so a finding points
    the analyst back at the source. Structurally identical to
    ``secret_scan.SecretSource`` so the orchestrator can feed both the same
    corpus."""

    label: str
    content: str
    location: str = ""


@dataclass
class IamClueTarget:
    sources: list[IamClueSource] = field(default_factory=list)
    # In-scope URLs whose body should be fetched and scanned (JS bundles,
    # exposed IaC files).
    fetch_urls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Clue:
    """One extracted identifier. ``value`` is the masked, safe-to-store form
    (account ids partially masked); ``extra`` holds parsed fields for the
    evidence dict."""

    kind: str
    value: str
    start: int
    end: int
    extra: tuple[tuple[str, str], ...] = ()


def _mask_account(account: str) -> str:
    """Partially mask a 12-digit AWS account id (``1234******90``): enough to
    correlate it without disclosing the full id. Non-12-digit input is fully
    masked."""
    if len(account) == 12 and account.isdigit():
        return f"{account[:4]}{'*' * 6}{account[-2:]}"
    return "*" * len(account)


def _split_resource(resource: str) -> tuple[str, str]:
    """Split an ARN resource into (type, name), e.g. ``role/Admin`` ->
    ``("role", "Admin")`` and ``function:my-fn`` -> ``("function", "my-fn")``.
    A bare resource with no separator is all name."""
    for sep in ("/", ":"):
        if sep in resource:
            rtype, _, name = resource.partition(sep)
            return rtype, name
    return "", resource


def _extract(text: str) -> list[_Clue]:
    """Find every IAM/ARN clue in ``text``."""
    clues: list[_Clue] = []

    for m in _ARN_RE.finditer(text):
        partition = m.group("partition")
        service = m.group("service")
        region = m.group("region")
        account = m.group("account")
        resource = m.group("resource").rstrip(".,;")
        rtype, rname = _split_resource(resource)
        masked_account = _mask_account(account)
        value = f"arn:{partition}:{service}:{region}:{masked_account}:{resource}"
        clues.append(
            _Clue(
                kind="arn",
                value=value,
                start=m.start(),
                end=m.end(),
                extra=(
                    ("aws_service", service),
                    ("aws_partition", partition),
                    ("resource_type", rtype),
                    ("resource_name", rname),
                    ("account_hint", masked_account),
                ),
            )
        )

    for m in _ASSUME_ROLE_RE.finditer(text):
        clues.append(
            _Clue(kind="assume-role", value=m.group(0), start=m.start(), end=m.end())
        )

    for m in _ROLE_NAME_RE.finditer(text):
        name = m.group(1)
        clues.append(
            _Clue(
                kind="role-name",
                value=name,
                start=m.start(1),
                end=m.end(1),
                extra=(("resource_name", name),),
            )
        )

    for m in _ACCOUNT_ID_RE.finditer(text):
        masked = _mask_account(m.group(1))
        clues.append(
            _Clue(
                kind="account-id",
                value=masked,
                start=m.start(1),
                end=m.end(1),
                extra=(("account_hint", masked),),
            )
        )

    clues.sort(key=lambda c: c.start)
    return clues


class IamClueScanner(BaseScanner):
    name = "iam_clue_scan"
    requires_tenant_pair = False
    # Reading already-available text / fetching an in-scope file is passive.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        http_engine: HttpEngine | None = None,
    ) -> None:
        self.scope = scope_manager
        # http_engine is only needed when fetch_urls is used; scanning provided
        # sources works with neither (offline).
        self.http = http_engine

    def _context(self, text: str, clue: _Clue) -> str:
        start = max(0, clue.start - _CONTEXT_WINDOW)
        end = min(len(text), clue.end + _CONTEXT_WINDOW)
        snippet = text[start:end]
        # Redact any real secret (not the identifier itself) that happens to sit
        # next to the clue, then mask any raw 12-digit account id in the
        # surrounding text, before this snippet is stored.
        redacted = sanitize_text(snippet)
        redacted = _ACCOUNT_IN_TEXT_RE.sub(lambda m: _mask_account(m.group()), redacted)
        return redacted.replace("\n", " ").strip()

    def _fetch(self, url: str) -> IamClueSource | None:
        """Fetch one in-scope URL's body as a source. Returns None when there
        is no engine, the URL is out of scope, or the request fails."""
        if self.http is None:
            return None
        if self.scope is not None and not self.scope.is_in_scope(url):
            return None
        try:
            resp = self.http.request(method="GET", url=url, headers={})
        except Exception:
            return None
        return IamClueSource(label=url, content=resp.text or "", location=url)

    def _severity(self, clue: _Clue) -> str:
        if clue.kind == "arn":
            service = dict(clue.extra).get("aws_service", "")
            if service in _IAM_SERVICES:
                return "low"
        return _KIND_SEVERITY.get(clue.kind, "info")

    def run(self, target: IamClueTarget) -> list[Finding]:
        sources: list[IamClueSource] = list(target.sources)
        for url in target.fetch_urls:
            fetched = self._fetch(url)
            if fetched is not None:
                sources.append(fetched)

        findings: list[Finding] = []
        # Dedup an identical clue seen across many sources (the same ARN
        # hardcoded in several bundles is one leak), keyed on (kind, value).
        seen: set[tuple[str, str]] = set()

        for source in sources:
            text = source.content or ""
            is_iac = looks_like_iac(source.location or source.label)
            for clue in _extract(text):
                key = (clue.kind, clue.value)
                if key in seen:
                    continue
                seen.add(key)

                evidence = {
                    "clue_kind": clue.kind,
                    "value": clue.value,
                    "source_label": source.label,
                    "source_location": source.location,
                    "source_is_iac": is_iac,
                    "context": self._context(text, clue),
                    "note": (
                        "Identifier/hint only - NOT a live credential and NOT "
                        "used against AWS. Pair with --iam-file to corroborate "
                        "reachable privilege escalation."
                    ),
                }
                evidence.update(dict(clue.extra))

                findings.append(
                    Finding(
                        asset=source.location or source.label,
                        category=f"iam-clue-{clue.kind}",
                        severity=self._severity(clue),
                        confidence=_KIND_CONFIDENCE.get(clue.kind, 0.5),
                        discovery_source="scanner",
                        evidence=evidence,
                        remediation=_REMEDIATION,
                    )
                )

        return findings
