"""pydantic schema for validating YAML rules before they are executed.

Fields beyond the classic (Nuclei-style) rule shape:
  authorization.mode                 : passive | active | destructive
  authorization.requires_tenant_pair : bool  (for modules like BOLA)
  authorization.requires_owned_infra : bool  (for modules like IMDS SSRF)

A matcher is deliberately small and declarative - just enough to express
the checks Wily converts from Python into YAML (status / word / regex),
plus a ``dsl`` escape hatch that the generic runner records as
"unsupported here" rather than silently passing (it needs an external
piece such as an out-of-band callback - see templates/matcher.py).
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"  # always excluded from an ordinary scan


class MatcherType(str, Enum):
    STATUS = "status"
    WORD = "word"
    REGEX = "regex"
    DSL = "dsl"


class MatcherPart(str, Enum):
    BODY = "body"
    HEADER = "header"
    STATUS = "status"


class MatcherCondition(str, Enum):
    AND = "and"
    OR = "or"


class Authorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    mode: AuthorizationMode = AuthorizationMode.PASSIVE
    requires_tenant_pair: bool = Field(default=False, alias="requires-tenant-pair")
    requires_owned_infra: bool = Field(default=False, alias="requires-owned-infra")


class TemplateInfo(BaseModel):
    name: str
    severity: Severity
    category: str
    description: str | None = None


class RuleRequest(BaseModel):
    method: str
    path: str
    headers: dict[str, str] | None = None
    body: str | None = None


class RuleMatcher(BaseModel):
    """One matcher. ``type`` selects which field carries the condition:

      * ``status`` -> ``status`` (a list of acceptable HTTP status codes)
      * ``word``   -> ``words``  (substrings to find, in ``part``)
      * ``regex``  -> ``regex``  (patterns to search for, in ``part``)
      * ``dsl``    -> ``dsl``    (expressions the generic runner cannot
                                  evaluate on its own; see matcher.py)

    ``condition`` combines the items *inside* a single matcher (all of the
    words vs. any of them); ``matchers-condition`` on the Template combines
    the matchers with each other. ``negative`` inverts a matcher (fires when
    it does *not* match).
    """

    model_config = ConfigDict(use_enum_values=True)

    type: MatcherType
    part: MatcherPart = MatcherPart.BODY
    words: list[str] | None = None
    regex: list[str] | None = None
    status: list[int] | None = None
    dsl: list[str] | None = None
    condition: MatcherCondition = MatcherCondition.AND
    negative: bool = False


class Template(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    info: TemplateInfo
    asset_type: str = Field(alias="asset-type")
    # When a rule is the YAML twin of a code scanner, set this to the code
    # scanner's evidence["technique"] value so the two collapse in the
    # deterministic dedup pass (risk/rules_engine) instead of double-reporting
    # the same issue. Defaults to the rule id (unique, so standalone rules are
    # never merged with anything).
    dedup_technique: str | None = Field(default=None, alias="dedup-technique")
    authorization: Authorization = Authorization()
    # Named values interpolated into request paths/headers/body and into
    # matcher words/regex via {{name}} (plus the built-ins BaseURL / Hostname).
    variables: dict[str, str] = {}
    request: list[RuleRequest]
    matchers: list[RuleMatcher]
    matchers_condition: MatcherCondition = Field(
        default=MatcherCondition.AND, alias="matchers-condition"
    )
    evidence: list[str] = []
    remediation: str | None = None
