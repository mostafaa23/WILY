"""Mutation-based cloud resource name generation.

Builds candidate bucket/storage names from one or more keywords (typically
the target's own name) combined with mutation words, instead of requiring
a pre-written wordlist file. For each keyword, emits the bare keyword plus
six combined forms per mutation word (``.``/``-``/no separator, both
orders). Pure/offline; the cloud-storage scanner that consumes the
generated names enforces scope and safety.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

__all__ = [
    "DEFAULT_ENVIRONMENTS",
    "DEFAULT_MUTATIONS",
    "aws_signal_reason",
    "azure_account_name",
    "build_combo_names",
    "build_names",
    "clean_text",
    "detect_aws_signal",
    "extract_seeds",
    "generate_candidates",
    "keyword_from_domain",
    "load_mutations",
    "valid_gcp_name",
    "valid_s3_name",
]

# A small, high-signal default mutation set. Kept intentionally short so the
# default run stays bounded (1 + 6N names per keyword); point --cloud-enum-
# wordlist at a larger list (e.g. cloud_enum's fuzz.txt) for a deeper sweep.
DEFAULT_MUTATIONS: tuple[str, ...] = (
    "dev", "development", "prod", "production", "stage", "staging", "test",
    "qa", "sandbox", "demo", "backup", "backups", "bak", "archive", "old",
    "data", "db", "database", "dump", "logs", "log", "assets", "static",
    "media", "images", "img", "uploads", "files", "public", "private",
    "internal", "external", "www", "web", "app", "api", "cdn", "admin",
    "config", "secret", "secrets", "keys", "temp", "tmp", "cache", "store",
    "storage", "bucket", "s3", "content", "documents", "docs", "download",
    "downloads", "resources", "users", "user", "client", "clients",
)

# Separators cloud_enum combines a keyword and a mutation with (plus "" = none).
_SEPARATORS = (".", "-", "")

# Environment words used by the three-part (keyword + mutation + environment)
# expansion, e.g. ``acme-assets-dev``. Deliberately short: every entry adds
# (mutations x patterns x separators) names per keyword.
DEFAULT_ENVIRONMENTS: tuple[str, ...] = (
    "dev", "development", "stage", "staging", "test", "qa", "prod", "production",
)

# Separators for the three-part expansion. "." is left out: dotted names break
# virtual-hosted S3 TLS and are rare in practice, and dropping it cuts the
# combo count by a third.
_COMBO_SEPARATORS = ("-", "")

# Three-part layouts, highest-signal first so a cap keeps the likeliest names.
_COMBO_PATTERNS = (
    "{kw}{s}{mut}{s}{env}",   # acme-assets-dev
    "{mut}{s}{kw}{s}{env}",   # assets-acme-dev
    "{kw}{s}{env}{s}{mut}",   # acme-dev-assets
    "{env}{s}{kw}{s}{mut}",   # dev-acme-assets
)

# cloud_enum's clean_text: lowercase, then drop anything outside [a-z0-9.-].
_CLEAN_RE = re.compile(r"[^a-z0-9.\-]")

# S3 / GCP bucket naming: 3-63 chars, lowercase alphanumerics, dots, hyphens.
_S3_NAME_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]")
# Azure storage account: 3-24 lowercase alphanumerics only (no dots/hyphens).
_AZURE_NAME_RE = re.compile(r"[a-z0-9]{3,24}")


def clean_text(text: str) -> str:
    """Lowercase ``text`` and strip every character outside ``[a-z0-9.-]``."""
    return _CLEAN_RE.sub("", (text or "").lower())


def valid_s3_name(name: str) -> bool:
    """True for a syntactically valid S3/GCP bucket name (3-63 chars)."""
    return bool(3 <= len(name) <= 63 and _S3_NAME_RE.fullmatch(name))


# GCP bucket names follow the same shape here (underscores are legal in GCP but
# are never produced by this generator, so the S3 validator is sufficient).
valid_gcp_name = valid_s3_name


def azure_account_name(name: str) -> str | None:
    """Reduce a candidate to a valid Azure storage-account name, or None.

    Azure accounts are lowercase alphanumerics only, 3-24 chars - so the dots
    and hyphens in a generated name are removed, and the result is accepted
    only if what remains is 3-24 alphanumerics.
    """
    stripped = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return stripped if _AZURE_NAME_RE.fullmatch(stripped) else None


def build_names(keywords: list[str], mutations: list[str]) -> list[str]:
    """Generate candidate names from keywords x mutations (cloud_enum-style).

    For each cleaned keyword: the bare keyword, then for each cleaned mutation
    the six forms ``{kw}{mut}``, ``{kw}.{mut}``, ``{kw}-{mut}`` and the three
    reversed forms. Order is preserved and exact duplicates are collapsed. Only
    names of length <= 63 are kept (the bucket-name ceiling).
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        if candidate and len(candidate) <= 63 and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    cleaned_mutations = [m for m in (clean_text(m) for m in mutations) if m]
    for raw_kw in keywords:
        base = clean_text(raw_kw)
        if not base:
            continue
        _add(base)
        for mut in cleaned_mutations:
            for sep in _SEPARATORS:
                _add(f"{base}{sep}{mut}")
                _add(f"{mut}{sep}{base}")
    return out


def build_combo_names(
    keywords: list[str],
    mutations: list[str],
    environments: list[str] | None = None,
) -> list[str]:
    """Three-part names: keyword + mutation + environment (lazys3-style).

    For each cleaned keyword, mutation and environment, emits the layouts in
    :data:`_COMBO_PATTERNS` with ``-`` and with no separator, e.g.
    ``acme-assets-dev``, ``assets-acme-dev``, ``acme-dev-assets``,
    ``dev-acme-assets``. A mutation equal to the environment is skipped (no
    ``acme-dev-dev``). Only valid S3 names are kept, deduplicated, in priority
    order: separator, then pattern, then environment, then mutation - so the
    ``-`` forms of the first layout come first and survive a cap.
    """
    envs = environments if environments is not None else list(DEFAULT_ENVIRONMENTS)
    cleaned_envs = [e for e in (clean_text(e) for e in envs) if e]
    cleaned_mutations = [m for m in (clean_text(m) for m in mutations) if m]
    out: list[str] = []
    seen: set[str] = set()
    for raw_kw in keywords:
        base = clean_text(raw_kw)
        if not base:
            continue
        for sep in _COMBO_SEPARATORS:
            for pattern in _COMBO_PATTERNS:
                for env in cleaned_envs:
                    for mut in cleaned_mutations:
                        if mut == env:
                            continue
                        name = pattern.format(kw=base, mut=mut, env=env, s=sep)
                        if name not in seen and valid_s3_name(name):
                            seen.add(name)
                            out.append(name)
    return out


def generate_candidates(
    keywords: list[str],
    mutations: list[str] | None = None,
    *,
    max_candidates: int | None = None,
    combos: bool = False,
    environments: list[str] | None = None,
) -> list[str]:
    """Top-level helper: build candidate names and optionally cap the count.

    ``mutations`` defaults to :data:`DEFAULT_MUTATIONS`. With ``combos=True``
    the three-part names from :func:`build_combo_names` are appended after the
    two-part ones (so the two-part set is always probed first). ``max_candidates``
    bounds the output so an enormous wordlist cannot blow up the number of live
    probes - the first ``max_candidates`` (keyword-first order) are kept.
    """
    muts = list(mutations) if mutations is not None else list(DEFAULT_MUTATIONS)
    names = build_names(list(keywords), muts)
    if combos:
        seen = set(names)
        for name in build_combo_names(list(keywords), muts, environments):
            if name not in seen:
                seen.add(name)
                names.append(name)
    if max_candidates is not None and max_candidates >= 0:
        names = names[:max_candidates]
    return names


def load_mutations(path: str | Path) -> list[str]:
    """Load a mutations wordlist (one entry per line), cloud_enum's fuzz.txt
    format. Blank lines are dropped; no comment/weight syntax is assumed."""
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return [line.strip() for line in text.splitlines() if line.strip()]


def keyword_from_domain(domain: str) -> str:
    """Derive a default enumeration keyword from a domain: its registrable
    label (e.g. ``example`` from ``api.example.co.uk``). A pragmatic heuristic -
    the second-level label - not a full public-suffix lookup."""
    host = (domain or "").strip().lower().strip(".")
    # Drop a scheme/path if a URL slipped through.
    host = re.sub(r"^[a-z]+://", "", host).split("/", 1)[0].split(":", 1)[0]
    labels = [label for label in host.split(".") if label]
    if not labels:
        return ""
    if len(labels) == 1:
        return clean_text(labels[0])
    # Handle common two-part TLDs (co.uk, com.au, ...) by taking the label
    # before them when present.
    two_part = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(labels) >= 3 and labels[-2] in two_part and len(labels[-1]) == 2:
        return clean_text(labels[-3])
    return clean_text(labels[-2])


# ---------------------------------------------------------------------------
# Phase 3: automatic seed (keyword) extraction
#
# Mine high-signal enumeration keywords from material a scan has ALREADY
# gathered - the target domain, response/JS bodies, and response headers - so
# name generation is context-aware instead of depending only on
# ``--cloud-keyword``. Pure/offline: callers pass text and headers; nothing is
# fetched here. The output feeds the same keyword list the generators consume,
# and the orchestrator keeps the per-keyword budget cap so a few extra seeds
# can never explode the probe count.
# ---------------------------------------------------------------------------

_MIN_SEED_LEN = 3
_MAX_SEED_LEN = 40

# Tokens that make poor seeds: generic infra/file words, cloud-provider words,
# common page words, and the mutation/environment words (which are combined
# with seeds separately, so using one as a seed only yields mutation x mutation
# noise). Everything here is dropped from the extracted seed list.
_SEED_STOPWORDS: frozenset[str] = frozenset(
    {
        "www", "com", "net", "org", "io", "co", "gov", "edu", "ac",
        "http", "https", "html", "json", "xml", "css", "js", "svg", "png",
        "amazonaws", "cloudfront", "s3", "aws", "ec2", "azure", "blob", "core",
        "windows", "googleapis", "google", "gcp", "cloud", "storage",
        "true", "false", "null", "none", "undefined", "the", "and", "for",
        "bucket", "buckets", "object", "objects", "region", "role", "arn",
        "login", "logout", "signin", "signup", "home", "welcome", "dashboard",
        "page", "error", "loading", "index", "main", "portal", "console",
        "site", "sites", "name", "title", "corp", "inc", "ltd", "llc",
    }
    | {m.lower() for m in DEFAULT_MUTATIONS}
    | {e.lower() for e in DEFAULT_ENVIRONMENTS}
)

# Cloud-storage references: an existing bucket/account name reveals the target's
# naming convention, so its org token(s) are the strongest seeds we can mine.
_SEED_S3_HOST_RE = re.compile(
    r"([a-z0-9][a-z0-9._\-]{1,61})\.s3[a-z0-9.\-]*\.amazonaws\.com", re.IGNORECASE
)
_SEED_S3_PATH_RE = re.compile(
    r"s3[a-z0-9.\-]*\.amazonaws\.com/([a-z0-9][a-z0-9._\-]{1,61})", re.IGNORECASE
)
_SEED_S3_URI_RE = re.compile(r"s3://([a-z0-9][a-z0-9._\-]{1,61})", re.IGNORECASE)
_SEED_AZURE_RE = re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.IGNORECASE)
_SEED_GCS_HOST_RE = re.compile(
    r"([a-z0-9][a-z0-9._\-]{1,61})\.storage\.googleapis\.com", re.IGNORECASE
)
_SEED_GCS_PATH_RE = re.compile(
    r"storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61})", re.IGNORECASE
)
_SEED_BUCKET_RES = (
    _SEED_S3_HOST_RE,
    _SEED_S3_PATH_RE,
    _SEED_S3_URI_RE,
    _SEED_AZURE_RE,
    _SEED_GCS_HOST_RE,
    _SEED_GCS_PATH_RE,
)
# An ARN's resource field often carries the org token (role/<org>-admin,
# bucket <org>-logs). The resource is everything after the 5th colon.
_SEED_ARN_RE = re.compile(
    r"arn:aws[a-z0-9\-]*:[a-z0-9\-]+:[a-z0-9\-]*:\d*:([A-Za-z0-9\-_./:*@+=]+)", re.IGNORECASE
)

# HTML brand tokens: the page title and a few brand-bearing <meta> tags.
_SEED_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SEED_META_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_SEED_META_NAME_RE = re.compile(
    r'(?:name|property)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_SEED_META_CONTENT_RE = re.compile(r'content\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SEED_META_BRAND_KEYS = frozenset(
    {"og:site_name", "application-name", "author", "apple-mobile-web-app-title"}
)

# Headers whose VALUE carries a product/org token worth seeding.
_SEED_PRODUCT_HEADERS = frozenset(
    {"server", "x-powered-by", "via", "x-generator", "x-application"}
)
# Leading segment of a custom ``X-<org>-...`` header that is generic, not an org.
_SEED_GENERIC_HEADER_SEGMENTS = frozenset(
    {
        "forwarded", "real", "powered", "frame", "content", "request",
        "requested", "correlation", "trace", "amz", "amzn", "cache",
        "ratelimit", "rate", "api", "csrf", "xss", "download", "response",
        "runtime", "served", "ua", "dns", "span", "parent", "client", "http",
        "with", "host", "auth", "token", "key", "version", "time",
        "generator", "application", "server",
    }
)
# Header names that carry an environment/deployment token.
_SEED_ENV_HEADER_RE = re.compile(r"(?i)^(?:x-)?(?:env|environment|stage|deployment|deploy)$")


def _seed_token_ok(token: str) -> bool:
    """A single cleaned token is a usable seed when it is the right length, not
    a generic/mutation stopword, and not a bare number."""
    return (
        _MIN_SEED_LEN <= len(token) <= _MAX_SEED_LEN
        and token not in _SEED_STOPWORDS
        and not token.isdigit()
    )


def _split_label(label: str) -> list[str]:
    """Split a bucket/host/ARN-resource label into parts on ``- . _ / :``."""
    return [p for p in re.split(r"[-._/:]+", (label or "").lower()) if p]


def _word_tokens(text: str) -> list[str]:
    """Split free text into lowercase alphanumeric word tokens."""
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t]


def _iter_headers(
    headers: Iterable[tuple[str, str]] | Mapping[str, str],
) -> list[tuple[str, str]]:
    """Normalize ``headers`` (a mapping or an iterable of pairs) to a pair list."""
    if isinstance(headers, Mapping):
        return [(str(k), str(v)) for k, v in headers.items()]
    out: list[tuple[str, str]] = []
    for item in headers or ():
        try:
            name, value = item
        except (TypeError, ValueError):
            continue
        out.append((str(name), str(value)))
    return out


def extract_seeds(
    *,
    domain: str | None = None,
    texts: Iterable[str] = (),
    headers: Iterable[tuple[str, str]] | Mapping[str, str] = (),
    max_seeds: int = 12,
) -> list[str]:
    """Mine high-signal cloud-enum seed keywords from already-gathered material.

    Pure/offline - callers pass text that a scan already retrieved (response
    and JS bodies) and the headers it already saw; nothing is fetched. Sources,
    highest-signal first:

      * ``domain`` -> its registrable label (via :func:`keyword_from_domain`).
      * Cloud-storage references inside ``texts`` -> the org token(s) of any S3
        / Azure Blob / GCS bucket or AWS ARN mentioned (an existing bucket name
        reveals the target's naming convention).
      * ``headers`` -> product tokens (``Server`` / ``X-Powered-By`` / ``Via``),
        the org token of a custom ``X-<org>-*`` header, and env tokens from an
        environment header.
      * HTML ``<title>`` and brand ``<meta>`` tags -> brand words.

    Each candidate is cleaned (:func:`clean_text`), filtered against a stop set
    (generic infra/page words and the mutation/environment words, which are
    applied separately), deduplicated preserving first-seen order, and the list
    is capped at ``max_seeds`` so a noisy page cannot inflate the probe budget.
    """
    seeds: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        token = clean_text(raw).strip(".-")
        if token and _seed_token_ok(token) and token not in seen:
            seen.add(token)
            seeds.append(token)

    # 1. Domain label (highest signal). Kept whole, matching keyword_from_domain.
    if domain:
        kw = keyword_from_domain(domain)
        if kw:
            _add(kw)

    text_blob = "\n".join(t for t in texts if t)

    # 2. Cloud-storage references: mine org tokens from bucket/account labels
    #    and ARN resources.
    for rex in _SEED_BUCKET_RES:
        for match in rex.finditer(text_blob):
            for seg in _split_label(match.group(1)):
                _add(seg)
    for match in _SEED_ARN_RE.finditer(text_blob):
        for seg in _split_label(match.group(1)):
            _add(seg)

    # 3. Headers: product tokens, custom X-<org>- tokens, env tokens.
    for name, value in _iter_headers(headers):
        lname = name.strip().lower()
        if lname in _SEED_PRODUCT_HEADERS:
            for tok in _word_tokens(value):
                _add(tok)
        elif lname.startswith("x-") and lname.count("-") >= 2:
            seg = lname.split("-")[1]
            if seg not in _SEED_GENERIC_HEADER_SEGMENTS:
                _add(seg)
        if _SEED_ENV_HEADER_RE.match(lname):
            for tok in _word_tokens(value):
                _add(tok)

    # 4. HTML brand tokens (title + selected meta content), lowest priority.
    for match in _SEED_TITLE_RE.finditer(text_blob):
        for tok in _word_tokens(match.group(1)):
            _add(tok)
    for tag in _SEED_META_RE.finditer(text_blob):
        raw = tag.group(0)
        nm = _SEED_META_NAME_RE.search(raw)
        ct = _SEED_META_CONTENT_RE.search(raw)
        if nm and ct and nm.group(1).lower() in _SEED_META_BRAND_KEYS:
            for tok in _word_tokens(ct.group(1)):
                _add(tok)

    return seeds[:max_seeds]


# ---------------------------------------------------------------------------
# Phase 3: AWS-signal detection (auto-trigger)
#
# When a scan observes an AWS footprint, the cloud-enum pass is worth running
# even without ``--cloud-enum``. These helpers decide that from material the
# scan already has - high-precision markers in observed text, and (reusing
# Phase 1) the categories of findings already produced (``iam-clue-*`` ARNs,
# S3 bucket findings) - rather than re-parsing JS. The orchestrator keeps the
# budget cap, so auto-enabling never widens scope or explodes the probe count.
# ---------------------------------------------------------------------------

_AWS_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("amazonaws.com host", re.compile(r"\bamazonaws\.com\b", re.IGNORECASE)),
    ("s3:// URI", re.compile(r"s3://[a-z0-9]", re.IGNORECASE)),
    ("AWS ARN", re.compile(r"\barn:aws[a-z0-9\-]*:", re.IGNORECASE)),
    ("CloudFront host", re.compile(r"\b[a-z0-9]+\.cloudfront\.net\b", re.IGNORECASE)),
)


def detect_aws_signal(text: str) -> str | None:
    """Return a short reason label if ``text`` contains a high-precision AWS
    marker (amazonaws.com host, ``s3://`` URI, an ARN, or a CloudFront host),
    else ``None``. Deliberately narrow so a stray word like ``lambda`` is not
    mistaken for an AWS footprint."""
    if not text:
        return None
    for reason, pattern in _AWS_SIGNAL_PATTERNS:
        if pattern.search(text):
            return reason
    return None


def aws_signal_reason(
    *,
    findings_categories: Iterable[str] = (),
    texts: Iterable[str] = (),
) -> str | None:
    """Decide whether an AWS signal justifies auto-enabling cloud-enum.

    Checks the categories of findings already produced first (reusing Phase 1's
    ``iam-clue-*`` ARN/IAM clues and any S3/AWS finding rather than re-parsing),
    then high-precision markers in the observed ``texts``. Returns a human reason
    for the console line, or ``None`` when no AWS signal is present.
    """
    for cat in findings_categories:
        c = (cat or "").lower()
        if c.startswith("iam-clue-"):
            return f"IAM/ARN clue finding ({cat})"
        if "s3" in c or "aws" in c:
            return f"AWS finding ({cat})"
    for text in texts:
        reason = detect_aws_signal(text)
        if reason:
            return f"{reason} observed"
    return None
