"""The unified orchestrator: ``wily scan <domain>``.

Runs Auth Bypass and SSRF levels 1+2 automatically against every endpoint
it discovers. JWT Tampering, BOLA, IAM Privesc, and blind SSRF (level 4)
each enable themselves once their required input is supplied (--token,
--identity, --iam-file, --blind respectively).

Safety gates: destructive-method auth-bypass testing needs
--confirm-destructive; SSRF/IMDS needs --confirm-owned-infra, since it
must only target infrastructure the tester owns.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from wily.core.oob_canary import OOBCanaryServer
from wily.core.oob_interaction import ExternalOOBClient
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import (
    ScopeError,
    ScopeManager,
    extract_bucket_name,
    load_scope_config,
)
from wily.recon.api_discovery import (
    ApiDiscoveryPipeline,
    DiscoveryConfig,
    DiscoveryReport,
)
from wily.recon.cloud_enum import (
    aws_signal_reason,
    azure_account_name,
    extract_seeds,
    generate_candidates,
    keyword_from_domain,
    load_mutations,
)
from wily.recon.live_filter import filter_live_assets
from wily.recon.parameter_discovery import (
    ParameterDiscoveryConfig,
    discover_parameters,
    select_ssrf_candidates,
)
from wily.recon.subdomain_enum import enumerate_subdomains
from wily.recon.token_harvest import harvest_tokens, redact_jwt
from wily.recon.token_pool import load_token_pool, select_live_identities
from wily.recon.traffic_import import ImportedTraffic, import_traffic
from wily.report.html_report import export_html
from wily.report.json_report import export_json
from wily.report.sarif_report import export_sarif
from wily.risk.ml.dedup import cluster_by_endpoint_hash, deduplicate
from wily.risk.ml.feedback import FeedbackStore
from wily.risk.ml.model import load_triage_model
from wily.risk.ml.ranker import rank_findings
from wily.risk.rules_engine import apply_deterministic_rules
from wily.risk.scoring import compute_risk_score
from wily.risk.triggers import TriggerContext, derive_followups
from wily.scanners.authz_bypass import (
    AuthzBypassScanner,
    AuthzBypassTarget,
    CorsMisconfigScanner,
    CorsMisconfigTarget,
    StageInconsistencyScanner,
    StageInconsistencyTarget,
)
from wily.scanners.base import Finding, ScannerConfirmationError, run_scanner
from wily.scanners.bola import BolaTester, Identity
from wily.scanners.cloud_storage import CloudStorageScanner, CloudStorageTarget
from wily.scanners.http_engine import HttpEngine
from wily.scanners.iam_clue_scan import (
    IamClueScanner,
    IamClueSource,
    IamClueTarget,
    looks_like_iac,
)
from wily.scanners.iam_privesc import (
    build_privesc_graph,
    filter_principals_in_scope,
    find_privesc_paths,
    load_authorization_details,
)
from wily.scanners.jwt_secret import build_weak_hs256_finding, recover_hs256_secret
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget
from wily.scanners.php_shell import PhpShellScanner, PhpShellTarget
from wily.scanners.rule_scanner import RuleScanner, RuleScanTarget
from wily.scanners.s3_bucket import S3BucketScanner, S3BucketTarget, s3_host_for
from wily.scanners.secret_scan import (
    SecretScanScanner,
    SecretScanTarget,
    SecretSource,
)
from wily.scanners.session_fixation import (
    SessionFixationScanner,
    SessionFixationTarget,
)
from wily.scanners.ssrf_imds import SsrfImdsScanner, SsrfImdsTarget
from wily.scanners.takeover import TakeoverScanner, TakeoverTarget
from wily.scanners.timing_enum import TimingEnumScanner, TimingEnumTarget
from wily.scanners.tls_config import TlsConfigScanner, TlsConfigTarget
from wily.scanners.token_entropy import TokenEntropyScanner, TokenEntropyTarget
from wily.templates.loader import load_rules

console = Console(stderr=True)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# --- Performance / budget defaults -------------------------------------------
# These bound an otherwise-unbounded run so one large or slow target can no
# longer grind for hours and starve the rest. None of them weaken detection on
# a target that finishes inside its budget: they only cap worst-case time.
#
# How many endpoints of a SINGLE target are scanned at once. The scanners'
# blocking requests are offloaded to threads (scanners.base.run_scanner), so
# this many endpoints' checks genuinely overlap instead of running strictly one
# after another. All requests still go through the one shared, scope-enforcing
# HttpEngine and the per-host AdaptiveRateLimiter, so same-host traffic stays
# rate-limited; the speedup comes from overlapping the idle network wait.
_DEFAULT_ENDPOINT_CONCURRENCY = 8
# How many independent TARGETS (hosts) are scanned at once. Different hosts have
# their own ScopeManager / rate limiter / HttpEngine (a fresh set per
# run_full_scan call), so this is safe parallelism across hosts, which is where
# most of the real speedup on a big subdomain sweep comes from.
_DEFAULT_TARGET_CONCURRENCY = 3
# Per-target wall-clock budget (seconds). When a target's per-endpoint scan
# passes this, the remaining endpoints are skipped, whatever was already found
# is still written, and the run moves on - it never hangs on one host. 0 / None
# disables the budget (fully unbounded, pre-performance-work behaviour).
_DEFAULT_TARGET_TIMEOUT = 1200.0  # 20 minutes


@contextlib.contextmanager
def _domain_output(log_path: Path, *, verbose: bool):
    """Route every ``wily.*`` log record for one domain's scan into
    ``log_path`` (so the terminal is not flooded with per-request noise such as
    'Scope guard: refusing redirect ...'), and - unless ``verbose`` - silence
    the chatty ``console`` prints so only the progress bar and final summary
    show. Everything is restored on exit."""
    wily_logger = logging.getLogger("wily")
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    prev_level = wily_logger.level
    prev_quiet = console.quiet
    wily_logger.setLevel(logging.INFO)
    wily_logger.addHandler(handler)
    if not verbose:
        console.quiet = True
    try:
        yield
    finally:
        console.quiet = prev_quiet
        wily_logger.removeHandler(handler)
        handler.close()
        wily_logger.setLevel(prev_level)


def _dump_collected(artifacts_dir: Path, report, findings: list) -> None:
    """Persist the raw data a scan gathered - the discovered endpoints/URLs, any
    cloud-storage hits, and a counts summary - under ``<domain>/collected/`` so
    it can be revisited later, separate from the final findings report."""
    coll = Path(artifacts_dir) / "collected"
    coll.mkdir(parents=True, exist_ok=True)

    try:
        disc = report.to_json() if report is not None else {}
    except Exception:
        disc = {}
    endpoints = disc.get("endpoints", []) if isinstance(disc, dict) else []

    (coll / "discovery.json").write_text(
        json.dumps(disc, indent=2, default=str), encoding="utf-8"
    )
    (coll / "endpoints.txt").write_text(
        "\n".join(str(e) for e in endpoints) + ("\n" if endpoints else ""),
        encoding="utf-8",
    )

    s3_like = [
        {"asset": str(f.asset), "category": f.category, "severity": f.severity}
        for f in findings
        if any(k in f.category.lower() for k in ("s3", "bucket", "cloud", "storage", "takeover"))
    ]
    (coll / "s3.json").write_text(json.dumps(s3_like, indent=2), encoding="utf-8")

    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    access = (disc.get("stats") or {}).get("access") if isinstance(disc, dict) else None
    (coll / "summary.json").write_text(
        json.dumps(
            {
                "access": access,
                "endpoints_discovered": len(endpoints),
                "findings": len(findings),
                "by_severity": by_sev,
                "by_category": by_cat,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _print_scan_summary(status: Console, rows: list[tuple], out_dir: Path) -> None:
    """One summary table across all domains, printed after the progress bar."""
    table = Table(title="Scan summary")
    table.add_column("#", justify="right")
    table.add_column("Domain", overflow="fold")
    table.add_column("Findings", justify="right")
    table.add_column("Top severity")
    for i, (domain, findings, _ddir) in enumerate(rows, start=1):
        top = max(
            (f.severity for f in findings),
            key=lambda s: _SEVERITY_RANK.get((s or "").lower(), 0),
            default="-",
        )
        table.add_row(str(i), domain, str(len(findings)), top)
    status.print(table)
    total = sum(len(f) for _d, f, _p in rows)
    with_findings = sum(1 for _d, f, _p in rows if f)
    status.print(
        f"[green][+][/green] Done. {len(rows)} scanned, {with_findings} with "
        f"findings, {total} total. Reports in [bold]{out_dir.resolve()}[/bold]."
    )


def _soft_404_probe_url(ep_url: str, token: str | None = None) -> str:
    """Build a sibling URL that almost certainly does not exist on the target.

    The last path segment of ``ep_url`` is replaced with a random marker
    (``/api/users/1`` -> ``/api/users/wily-nx-<hex>``); a root URL becomes
    ``/wily-nx-<hex>``. Query and fragment are dropped. The Auth Bypass
    scanner fetches this once and suppresses a "missing authorizer" hit whose
    body matches it - the endpoint is then a catch-all / SPA shell / soft-404,
    not a real unauthenticated data leak. Using a sibling (same parent path)
    rather than a host-wide random path also catches per-prefix catch-alls
    such as ``/api/*`` that answer every unknown route with the same JSON.
    """
    parsed = urlparse(ep_url)
    marker = f"wily-nx-{token or secrets.token_hex(6)}"
    segments = parsed.path.split("/")
    # Drop a trailing empty segment ("/a/b/" -> ["", "a", "b"]) so the marker
    # replaces "b", not the empty string after the slash.
    while len(segments) > 1 and segments[-1] == "":
        segments.pop()
    if len(segments) <= 1:
        new_path = f"/{marker}"
    else:
        segments[-1] = marker
        new_path = "/".join(segments)
    return parsed._replace(path=new_path, params="", query="", fragment="").geturl()


_CLOUD_ENUM_DEFAULT_CAP = 400
_CLOUD_ENUM_COMBOS_DEFAULT_CAP = 3000


def _cloud_enum_cap(explicit: int | None, combos: bool, n_keywords: int = 1) -> int:
    """Resolve --cloud-enum-max: an explicit value wins; otherwise 400 per
    keyword (enough for the full built-in two-part list) or 3000 per keyword
    with combos. Scaling by keyword count keeps a second keyword from being
    starved, since names are generated keyword-first."""
    if explicit is not None:
        return explicit
    per_kw = _CLOUD_ENUM_COMBOS_DEFAULT_CAP if combos else _CLOUD_ENUM_DEFAULT_CAP
    return per_kw * max(1, n_keywords)


def _want_canary(*, blind: bool, auto_canary: bool, confirm_owned_infra: bool) -> bool:
    """Decide whether to stand up the OOB canary for this run.

    ``--blind`` forces it on (explicit override, even with ``--no-auto-canary``).
    Otherwise it auto-starts when ``--auto-canary`` is on AND the SSRF/IMDS
    module itself is enabled (``confirm_owned_infra``) - there is no point
    running a canary when the scanner that would use it is skipped, and gating
    on the same flag keeps the canary from ever widening the scan's reach
    beyond what SSRF already does.
    """
    return blind or (auto_canary and confirm_owned_infra)


def _start_oob_canary() -> tuple[OOBCanaryServer | None, OSError | None]:
    """Start a local OOB canary, returning ``(canary, None)`` on success or
    ``(None, error)`` when the listener cannot bind - so the caller falls back
    cleanly to the pre-auto behavior (no canary, no blind SSRF) instead of
    crashing."""
    try:
        return OOBCanaryServer(), None
    except OSError as exc:
        return None, exc


def _parse_bind(bind: str | None) -> tuple[str, int]:
    """Parse ``--oob-bind`` (``HOST``, ``HOST:PORT`` or ``:PORT``) into a
    ``(host, port)`` pair. Defaults to ``0.0.0.0:0`` (all interfaces, OS-chosen
    port) so a bare ``--oob-public-url`` still binds a reachable listener."""
    if not bind or not bind.strip():
        return "0.0.0.0", 0
    raw = bind.strip()
    if ":" in raw:
        host, _, port_s = raw.rpartition(":")
        host = host or "0.0.0.0"
        try:
            port = int(port_s) if port_s else 0
        except ValueError:
            port = 0
        return host, port
    return raw, 0


def _build_oob_interaction(
    *, oob_server: str | None, oob_bind: str | None, oob_public_url: str | None
) -> tuple[object | None, Exception | None, str]:
    """Pick and build the OOB backend for this run, returning
    ``(interaction, error, how_label)``.

    Precedence (all opt-in; the default stays the loopback canary):
      1. ``--oob-server`` -> a pluggable :class:`ExternalOOBClient` that polls a
         user-supplied interactsh-compatible server (works for remote targets,
         no inbound listener needed).
      2. ``--oob-bind`` / ``--oob-public-url`` -> a self-hosted canary bound to
         a reachable interface and advertising the public URL (remote targets).
      3. neither -> the loopback canary, exactly as before.
    """
    if oob_server:
        try:
            client = ExternalOOBClient(
                oob_server, interaction_domain=oob_public_url or oob_server
            )
            return client, None, f"external interaction server {client.base_url}"
        except Exception as exc:  # bad URL etc.; fall back cleanly
            return None, exc, "external"
    if oob_bind or oob_public_url:
        host, port = _parse_bind(oob_bind)
        try:
            canary = OOBCanaryServer(host=host, port=port, public_base_url=oob_public_url)
            return canary, None, f"self-hosted canary (bound {host}:{port}) at {canary.base_url}"
        except OSError as exc:
            return None, exc, "self-hosted"
    canary, error = _start_oob_canary()
    label = f"loopback canary at {canary.base_url}" if canary else "loopback"
    return canary, error, label


def read_targets_file(path: str | Path) -> list[str]:
    """Parse a targets file: one domain per line.

    Blank lines and lines whose first non-whitespace character is ``#`` (full-line
    comments) are ignored. Surrounding whitespace is stripped from each entry.
    Order is preserved. Raises ``OSError`` if the file cannot be read.
    """
    targets: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.append(stripped)
    return targets


def collect_targets(
    domains: list[str] | None, targets_file: str | Path | None
) -> list[str]:
    """Combine positional domains and a ``--targets-file`` into one ordered,
    de-duplicated target list.

    Positional args come first, then file entries; the first occurrence of each
    domain wins and later duplicates are dropped (dedup is on the trimmed string).
    """
    combined: list[str] = list(domains or [])
    if targets_file:
        combined += read_targets_file(targets_file)

    seen: set[str] = set()
    result: list[str] = []
    for raw in combined:
        target = raw.strip()
        if not target or target in seen:
            continue
        seen.add(target)
        result.append(target)
    return result


def sanitize_domain_filename(domain: str) -> str:
    """Filesystem-safe base name for a domain's report file.

    Strips any URL scheme, lowercases, and replaces every character outside
    ``[a-z0-9.-]`` with ``_`` so the result is a safe file stem on any OS.
    """
    name = domain
    if "://" in name:
        name = urlparse(name).hostname or name
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9.\-]", "_", name)
    name = name.strip("._-")
    return name or "target"


def _default_subdomain_output_dir(root: str) -> str:
    """Folder name to hold per-host reports when subdomains were discovered but
    no ``--output-dir`` was given (many hosts cannot share one ``-o`` file)."""
    return f"{sanitize_domain_filename(root)}-reports"


def _enumerate_and_merge(
    targets: list[str],
    *,
    output_dir: str | None,
    max_results: int | None,
    binary: str | None,
) -> tuple[list[str], str | None]:
    """Automatically expand each root target into its subfinder-discovered
    subdomains, so ``wily scan example.com`` also reaches ``api.``/``dev.``/...

    Returns ``(targets, output_dir)``:

    * When subdomains are found, the result holds roots + new subdomains, the
      full list is saved to ``<out_dir>/subdomains.txt`` (reusable via
      ``--targets-file``), and ``out_dir`` is the given ``--output-dir`` or one
      derived from the first root when none was given.
    * When subfinder is missing or finds nothing, the roots and the original
      ``output_dir`` are returned unchanged - a plain single-host scan behaves
      exactly as before, so this is safe to run by default.

    Passive and read-only; de-duplicates case-insensitively."""
    status = Console(stderr=True)
    roots = list(targets)
    seen = {t.strip().lower() for t in roots}
    discovered: list[str] = []
    warned_missing = False

    for root in roots:
        res = enumerate_subdomains(root, max_results=max_results, binary=binary)
        if not res.tool_available:
            # subfinder not installed: note it once, quietly, and scan the given
            # host(s) only - never turn a routine scan into an error.
            if not warned_missing:
                status.print(f"[dim][*] {res.error}[/dim]")
                warned_missing = True
            continue
        if res.error:
            status.print(f"[yellow][!][/yellow] subfinder ({root}): {res.error}")
        new = [s for s in res.subdomains if s not in seen]
        seen.update(new)
        discovered.extend(new)
        status.print(
            f"[green][+][/green] {root}: {len(res.subdomains)} subdomain(s) found "
            f"({len(new)} new)."
        )

    if not discovered:
        return roots, output_dir

    merged = roots + discovered
    out_dir = output_dir or _default_subdomain_output_dir(roots[0])
    path = Path(out_dir)
    path.mkdir(parents=True, exist_ok=True)
    (path / "subdomains.txt").write_text("\n".join(merged) + "\n", encoding="utf-8")
    if not output_dir:
        status.print(
            "[cyan][*][/cyan] No --output-dir given; writing one report folder per "
            f"host to [bold]{out_dir}[/bold]."
        )
    status.print(
        f"[cyan][*][/cyan] {len(merged)} total target(s) "
        f"({len(discovered)} discovered) saved to [bold]{path / 'subdomains.txt'}[/bold]."
    )
    return merged, out_dir


async def run_scans(
    *,
    targets: list[str],
    output: str,
    output_dir: str | None = None,
    verbose: bool = False,
    enum_subdomains: bool = False,
    subdomain_max: int | None = None,
    subfinder_path: str | None = None,
    concurrency: int = _DEFAULT_TARGET_CONCURRENCY,
    target_timeout: float | None = _DEFAULT_TARGET_TIMEOUT,
    max_duration: float | None = None,
    **scan_kwargs,
) -> dict[str, list]:
    """CLI-facing orchestrator: scan one or more domains, one report per domain.

    Returns a map of domain label -> that domain's post-triage findings, so the
    caller can apply a CI gate (``--fail-on``) over the same findings the
    reports contain.

    Performance budgets (all bound worst-case time without weakening detection
    on a target that finishes inside its budget):
      * ``concurrency`` independent targets are scanned at once. Different hosts
        each get their own ScopeManager / rate limiter / HttpEngine (a fresh set
        per ``run_full_scan``), so this is safe cross-host parallelism - the main
        win on a large subdomain sweep. Defaults to
        ``_DEFAULT_TARGET_CONCURRENCY``.
      * ``target_timeout`` is forwarded to each ``run_full_scan`` as its
        per-target wall-clock budget: a host that exceeds it stops scanning
        further endpoints, writes what it found, and the run moves on.
      * ``max_duration`` caps the whole run: once the elapsed time passes it, no
        new target is started (the remaining targets are recorded with no
        findings and noted). ``None`` means no overall cap.

    Backward compatibility is the design constraint:
      * No targets (e.g. ``--iam-file`` alone) -> a single legacy run with the
        ``-o`` output path and ``domain=None``.
      * Exactly one target and no ``--output-dir`` -> a single legacy run writing
        to the ``-o`` path, byte-for-byte identical to the old single-domain flow.
      * Multiple targets, or ``--output-dir`` given -> each domain is scanned
        into its OWN report at ``<output_dir>/<sanitized-domain>.json`` (plus
        ``.html``/``.sarif`` siblings when ``--format`` asks). Each domain is its
        own scope root, because every ``run_full_scan`` call builds a fresh
        ScopeManager, so findings never bleed across domains.
    """
    # Opt-in, single-URL probes (session fixation, timing enum, token entropy,
    # stage inconsistency). They target a tester-supplied URL, so they run ONCE
    # here, not per discovered target/subdomain; their findings are injected
    # into the first report via ``extra_findings``.
    optional_probes = scan_kwargs.pop("optional_probes", None)
    probe_findings: list = []
    if optional_probes is not None and optional_probes.any_enabled():
        probe_findings = await _run_optional_probes(
            optional_probes, allow_local=bool(scan_kwargs.get("allow_local", False))
        )

    # Optional passive subdomain expansion: turn each root into its live
    # subdomains (subfinder) before scanning, and persist the full target list.
    if enum_subdomains and targets:
        targets, output_dir = _enumerate_and_merge(
            targets,
            output_dir=output_dir,
            max_results=subdomain_max,
            binary=subfinder_path,
        )

    # No domain at all (IAM/Burp/HAR-only): preserve the legacy single-call path.
    if not targets:
        findings = await run_full_scan(
            domain=None, output=output, target_timeout=target_timeout,
            extra_findings=probe_findings, **scan_kwargs
        )
        return {"target": findings or []}

    # Single target, no explicit output dir: EXACT legacy behavior (plus the
    # per-target time budget, so one huge host no longer runs unbounded).
    if len(targets) == 1 and not output_dir:
        findings = await run_full_scan(
            domain=targets[0], output=output, target_timeout=target_timeout,
            extra_findings=probe_findings, **scan_kwargs
        )
        return {targets[0]: findings or []}

    # Multi-domain (or single-domain-into-a-dir): one FOLDER per domain, holding
    # that domain's report(s), a scan.log, and a collected/ data dump.
    out_dir = Path(output_dir) if output_dir else Path(output).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    # A separate, always-on console for the progress bar and the final summary,
    # so they still show even while the chatty per-scan `console` is silenced.
    status = Console(stderr=True)
    status.print(
        f"[cyan][*][/cyan] Scanning {len(targets)} target(s) -> "
        f"[bold]{out_dir.resolve()}[/bold] (a folder per domain)."
    )

    results: dict[str, list] = {}
    summary_rows: list[tuple] = []
    used_names: set[str] = set()
    run_started = time.monotonic()
    skipped_over_budget = 0

    # Pre-assign a unique folder per domain up front (deterministic, and safe to
    # do before any concurrency starts), so two inputs that sanitize to the same
    # stem - "a.com" and "https://a.com/" - still get distinct folders.
    domain_dirs: dict[str, Path] = {}
    for domain in targets:
        stem = sanitize_domain_filename(domain)
        candidate = stem
        suffix = 2
        while candidate in used_names:
            candidate = f"{stem}-{suffix}"
            suffix += 1
        used_names.add(candidate)
        domain_dirs[domain] = out_dir / candidate

    def _over_budget() -> bool:
        return (
            max_duration is not None
            and max_duration > 0
            and (time.monotonic() - run_started) >= max_duration
        )

    async def _scan_one(domain: str) -> None:
        nonlocal skipped_over_budget
        # Overall run budget: once elapsed time passes --max-duration, do not
        # start new targets - record them with no findings and note it, rather
        # than letting the run drag on indefinitely.
        if _over_budget():
            skipped_over_budget += 1
            results[domain] = []
            summary_rows.append((domain, [], domain_dirs[domain]))
            return

        domain_dir = domain_dirs[domain]
        domain_dir.mkdir(parents=True, exist_ok=True)
        per_domain_output = domain_dir / "report.json"
        with _domain_output(domain_dir / "scan.log", verbose=verbose):
            findings = await run_full_scan(
                domain=domain,
                output=str(per_domain_output),
                artifacts_dir=domain_dir,
                target_timeout=target_timeout,
                # The once-per-run opt-in probes land in the first domain's report.
                extra_findings=probe_findings if domain == targets[0] else None,
                **scan_kwargs,
            )
        results[domain] = findings or []
        summary_rows.append((domain, findings or [], domain_dir))

    if verbose:
        # Live, chatty per-domain output (the old behaviour), into the folders.
        # Kept sequential so the streamed per-request log stays readable.
        for index, domain in enumerate(targets, start=1):
            status.print(
                f"\n[bold cyan]=== [{index}/{len(targets)}] {domain} ===[/bold cyan]"
            )
            await _scan_one(domain)
    else:
        # Clean terminal: a progress bar, with up to ``concurrency`` independent
        # targets scanned at once. Each verbose line goes to the per-domain
        # scan.log instead.
        sem = asyncio.Semaphore(max(1, concurrency))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=status,
        ) as progress:
            task = progress.add_task(
                f"Scanning (up to {max(1, concurrency)} at once)...", total=len(targets)
            )

            async def _worker(domain: str) -> None:
                async with sem:
                    await _scan_one(domain)
                    progress.advance(task)

            await asyncio.gather(*(_worker(domain) for domain in targets))

    # Keep the summary in the original target order regardless of the order the
    # concurrent scans happened to finish in.
    order = {domain: i for i, domain in enumerate(targets)}
    summary_rows.sort(key=lambda row: order.get(row[0], len(order)))

    if skipped_over_budget:
        status.print(
            f"[yellow][!][/yellow] Overall time budget (--max-duration) reached: "
            f"{skipped_over_budget} target(s) not scanned."
        )
    _print_scan_summary(status, summary_rows, out_dir)
    return results


async def _scan_endpoints(
    *,
    endpoints: list[str],
    all_findings: list,
    scanned: set,
    scope,
    http_engine,
    canary,
    token: str | None,
    yaml_rules: list,
    confirm_destructive: bool,
    confirm_owned_infra: bool,
    endpoint_concurrency: int = _DEFAULT_ENDPOINT_CONCURRENCY,
    deadline: float | None = None,
) -> int:
    """Run the per-endpoint scanners (Auth Bypass, CORS, optional YAML rules,
    parameter-discovery -> SSRF, and JWT) across every discovered endpoint, with
    bounded concurrency.

    The old implementation walked the endpoints one at a time, awaiting each
    blocking scanner in turn; because a synchronous scanner stalled the whole
    event loop, a host with many endpoints could take hours. Here up to
    ``endpoint_concurrency`` endpoints are in flight at once, and
    ``scanners.base.run_scanner`` offloads each blocking scanner to a worker
    thread, so their network waits genuinely overlap. Concurrency is bounded by
    a semaphore and every request still flows through the single shared,
    scope-enforcing ``http_engine`` and its per-host ``AdaptiveRateLimiter``, so
    same-host traffic stays rate-limited exactly as before - the parallelism
    only fills the idle time between requests.

    ``deadline`` (a ``time.monotonic()`` value) is the per-target budget: once it
    passes, no further endpoints start their scanners; the endpoints already
    finished keep their findings and the scan proceeds to write them. Returns
    the number of endpoints skipped because the budget was exhausted.
    """
    sem = asyncio.Semaphore(max(1, endpoint_concurrency))
    skipped = 0

    async def _scan_one_endpoint(ep_url: str) -> None:
        nonlocal skipped
        async with sem:
            # Per-target budget: stop launching new endpoint work once the
            # wall-clock deadline has passed. Already-running endpoints finish;
            # the rest are skipped and reported, and whatever was found is kept.
            if deadline is not None and time.monotonic() >= deadline:
                skipped += 1
                return

            console.print(f"[cyan]  ->[/cyan] {ep_url}")
            # Accumulate into a local list, then extend the shared list once, so
            # a partially-scanned endpoint contributes all-or-nothing and the
            # shared aggregation stays simple under concurrency.
            local: list = []

            try:
                authz_scanner = AuthzBypassScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    confirm_destructive=confirm_destructive,
                )
                local += await run_scanner(
                    authz_scanner,
                    AuthzBypassTarget(
                        url=ep_url,
                        include_destructive_methods=confirm_destructive,
                        # Differential baseline: without it, every catch-all /
                        # SPA route or public page that answers 200 with no
                        # auth is reported as a critical missing authorizer.
                        soft_404_probe_url=_soft_404_probe_url(ep_url),
                    ),
                )
                local += await run_scanner(
                    CorsMisconfigScanner(scope_manager=scope, http_engine=http_engine),
                    CorsMisconfigTarget(url=ep_url),
                )
                scanned.add(("authz_bypass", ep_url))
                scanned.add(("cors_misconfig", ep_url))
            except ScannerConfirmationError as e:
                console.print(f"[yellow]    [!][/yellow] Auth Bypass skipped: {e}")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Auth Bypass failed: {e}")

            # --- Declarative YAML rules (opt-in via --rules). Runs the loaded
            # http-endpoint rules through the same scope/safety-enforcing engine.
            # Findings dedupe against the code scanners above when they overlap.
            if yaml_rules:
                try:
                    rule_scanner = RuleScanner(
                        rules=yaml_rules,
                        scope_manager=scope,
                        http_engine=http_engine,
                        confirm_owned_infra=confirm_owned_infra,
                    )
                    local += await run_scanner(
                        rule_scanner, RuleScanTarget(url=ep_url)
                    )
                    scanned.add(("rule_scanner", ep_url))
                except Exception as e:
                    console.print(f"[yellow]    [!][/yellow] YAML rules failed: {e}")

            try:
                # Use the full Arjun-derived wordlist (no artificial 300-param
                # cap) so uncommon URL/webhook/redirect parameter names that
                # back real SSRF are not missed.
                pconfig = ParameterDiscoveryConfig(url=ep_url, max_params=2000)
                # discover_parameters is a synchronous, potentially slow
                # call (up to max_params sequential HTTP requests). It is
                # offloaded to a worker thread so it never blocks this
                # coroutine's event loop while it runs.
                discovery_result = await asyncio.to_thread(
                    discover_parameters, pconfig, scope, http_engine
                )
                ssrf_params = select_ssrf_candidates(discovery_result)
                if discovery_result.probe_errors:
                    console.print(
                        f"[yellow]    [!][/yellow] Parameter discovery: "
                        f"{discovery_result.probe_errors}/{discovery_result.probes_sent} probes failed"
                    )
                for param_name in ssrf_params:
                    console.print(f"[cyan]    [*][/cyan] SSRF candidate: {param_name}")
                    ssrf_target = SsrfImdsTarget(
                        url=ep_url, param_name=param_name, canary_server=canary
                    )
                    ssrf_scanner = SsrfImdsScanner(
                        scope_manager=scope,
                        http_engine=http_engine,
                        confirm_owned_infra=confirm_owned_infra,
                    )
                    local += await run_scanner(ssrf_scanner, ssrf_target)
                    scanned.add(("ssrf_imds", ep_url))
            except ScannerConfirmationError as e:
                console.print(f"[yellow]    [!][/yellow] SSRF skipped: {e}")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Parameter discovery failed: {e}")

            if token:
                try:
                    # canary_server wires the OOB backend so jku + x5u header
                    # injection confirm via a real callback; check_weak_secret
                    # is off here because the weak-HS256 check already ran once
                    # centrally above (it is a token property, not per-endpoint).
                    jwt_target = JwtTarget(
                        url=ep_url,
                        sample_token=token,
                        canary_server=canary,
                        check_weak_secret=False,
                    )
                    local += await run_scanner(
                        JwtTamperScanner(scope_manager=scope, http_engine=http_engine),
                        jwt_target,
                    )
                    scanned.add(("jwt_tamper", ep_url))
                except Exception as e:
                    console.print(f"[yellow]    [!][/yellow] JWT check failed: {e}")

            # Mutate the caller's list in place (extend, not +=) so the shared
            # aggregation holds across all concurrent endpoint workers.
            all_findings.extend(local)

    await asyncio.gather(*(_scan_one_endpoint(ep) for ep in endpoints))

    if skipped:
        console.print(
            f"[yellow][!][/yellow] Per-target time budget reached: skipped "
            f"{skipped} of {len(endpoints)} endpoint(s). Partial results are "
            "still written (raise --target-timeout, or 0 to disable)."
        )
    return skipped


async def run_full_scan(
    domain: str,
    token: str | None,
    identities_raw: list[str],
    iam_file: str | None,
    allow_local: bool,
    blind: bool,
    output: str,
    token_pool: str | None = None,
    auto_token: bool = True,
    auto_canary: bool = True,
    report_formats: list[str] | None = None,
    confirm_destructive: bool = True,
    confirm_owned_infra: bool = True,
    confirm_s3_writes: bool = False,
    s3_lab_write: bool = False,
    probe_live: bool = False,
    cloud_enum: bool = False,
    cloud_keywords: list[str] | None = None,
    cloud_enum_wordlist: str | None = None,
    cloud_enum_max: int | None = None,
    cloud_enum_combos: bool = False,
    show_leak: bool = False,
    burp_xml: str | None = None,
    import_har: str | None = None,
    scope_buckets: list[str] | None = None,
    scope_accounts: list[str] | None = None,
    scope_config: str | None = None,
    feedback_store: str | None = None,
    use_rules: bool = False,
    jwt_secret_wordlist: str | None = None,
    oob_server: str | None = None,
    oob_bind: str | None = None,
    oob_public_url: str | None = None,
    ml_model: str | None = None,
    artifacts_dir: str | Path | None = None,
    endpoint_concurrency: int = _DEFAULT_ENDPOINT_CONCURRENCY,
    target_timeout: float | None = _DEFAULT_TARGET_TIMEOUT,
    extra_findings: list | None = None,
    php_shell_confirm: bool = False,
) -> list:
    # Seeded with any pre-computed findings (e.g. the once-per-run opt-in
    # probes) so they are triaged and written into this report like the rest.
    all_findings: list = list(extra_findings) if extra_findings else []

    # Per-target wall-clock budget. The per-endpoint scan loop below checks this
    # deadline and stops queueing new endpoints once it passes, so one large or
    # slow host can no longer run for hours - whatever was found so far is still
    # written and the run moves on. None / <=0 disables the budget entirely.
    deadline: float | None = None
    if target_timeout and target_timeout > 0:
        deadline = time.monotonic() + target_timeout

    # Optional extra wordlist for the weak-HS256-secret check. Loaded once,
    # one candidate per non-blank line; a bad path is a warning, not a failure.
    extra_jwt_secrets: list[str] = []
    if jwt_secret_wordlist:
        try:
            extra_jwt_secrets = [
                line.strip()
                for line in Path(jwt_secret_wordlist).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            console.print(
                f"[cyan][*][/cyan] JWT weak-secret: +{len(extra_jwt_secrets)} candidate(s) "
                f"from {jwt_secret_wordlist}."
            )
        except OSError as e:
            console.print(f"[yellow][!][/yellow] --jwt-secret-wordlist ignored: {e}")

    # --- Declarative YAML rules (opt-in). Loaded once; run per endpoint
    # alongside the code scanners when --rules is passed. Off by default, so
    # the existing code-based pipeline is byte-for-byte unchanged without it.
    yaml_rules = load_rules() if use_rules else []
    if use_rules:
        console.print(
            f"[cyan][*][/cyan] YAML rules: {len(yaml_rules)} loaded "
            "(--rules); run alongside the code scanners."
        )

    # --- Resolve the extended scope (buckets + AWS accounts) from CLI/config.
    buckets: tuple[str, ...] = tuple(scope_buckets or ())
    accounts: tuple[str, ...] = tuple(scope_accounts or ())
    excluded: tuple[str, ...] = ()
    if scope_config:
        try:
            cfg = load_scope_config(scope_config)
            buckets += cfg["buckets"]
            accounts += cfg["accounts"]
            excluded += cfg["exclude"]
        except (ScopeError, OSError) as e:
            console.print(f"[yellow][!][/yellow] Scope config ignored: {e}")
    if buckets:
        console.print(f"[cyan][*][/cyan] S3 bucket scope: {', '.join(buckets)}")
    if accounts:
        console.print(f"[cyan][*][/cyan] AWS account scope: {', '.join(accounts)}")

    # --- Hybrid input: parse any imported traffic (offline - no replay).
    imported: ImportedTraffic | None = None
    if burp_xml or import_har:
        imported = import_traffic(burp_xml=burp_xml, har=import_har)
        console.print(
            f"[cyan][*][/cyan] Imported traffic: {len(imported.endpoints)} endpoint(s), "
            f"{len(imported.tokens)} token(s), {len(imported.s3_links)} S3 link(s)."
        )
        for err in imported.errors:
            console.print(f"[yellow][!][/yellow] Traffic import: {err}")
        # Seed the JWT --token path from an observed bearer token when the user
        # did not supply one explicitly.
        if not token and imported.jwt_tokens:
            token = imported.jwt_tokens[0]
            console.print("[cyan][*][/cyan] JWT: seeded --token from imported bearer token.")

    if iam_file:
        console.print(f"[cyan][*][/cyan] IAM: analyzing {iam_file} ...")
        try:
            principals = load_authorization_details(Path(iam_file))
            if accounts:
                before = len(principals)
                principals = filter_principals_in_scope(principals, accounts)
                if len(principals) < before:
                    console.print(
                        f"[cyan][*][/cyan] IAM: {before - len(principals)} principal(s) "
                        "dropped as out-of-account-scope."
                    )
            graph = build_privesc_graph(principals)
            iam_findings = find_privesc_paths(graph, principals)
            all_findings += iam_findings
            console.print(f"[cyan][*][/cyan] IAM: {len(iam_findings)} finding(s).")
        except Exception as e:
            # A malformed/partial authorization-details file (missing keys,
            # bad JSON) must not abort the whole scan - skip IAM and continue
            # with the rest of the modules.
            console.print(f"[yellow][!][/yellow] IAM analysis skipped: {e}")

    # When no domain was supplied but imported traffic carried endpoints, adopt
    # the first imported endpoint's host as the scan target so those endpoints
    # can be scanned. Active discovery is skipped in that case (the tester chose
    # import mode, not "go probe this live target").
    user_supplied_domain = bool(domain)
    if not domain and imported and imported.endpoints:
        first_host = urlparse(imported.endpoints[0]).hostname
        if first_host:
            domain = first_host
            console.print(
                f"[cyan][*][/cyan] No domain given; scoping to imported host [bold]{first_host}[/bold]."
            )

    if not domain:
        return _finish(all_findings, output, show_leak, report_formats, feedback_store, ml_model)

    if domain.startswith("http"):
        target_url = domain
    else:
        scheme = "http" if allow_local else "https"
        target_url = f"{scheme}://{domain}"

    root_domain = urlparse(target_url).hostname or domain

    # One ScopeManager, one rate limiter, one HttpEngine for the entire
    # scan: every scanner below shares them, so the AdaptiveRateLimiter's
    # per-host backoff state (e.g. after a 429) carries across scanners
    # and endpoints instead of resetting on every single call.
    scope = ScopeManager(
        root_domain,
        allow_local_targets=allow_local,
        excluded_hosts=excluded,
        s3_buckets=buckets,
        aws_accounts=accounts,
    )
    rate_limiter = AdaptiveRateLimiter()
    http_engine = HttpEngine(scope_manager=scope, rate_limiter=rate_limiter)

    # A DiscoveryReport always exists so BOLA (which consumes the report
    # object) has one to work with, even in pure import mode.
    report = DiscoveryReport(target=target_url)
    endpoints: list[str] = []
    if user_supplied_domain:
        console.print(f"[cyan][*][/cyan] Discovering endpoints on [bold]{target_url}[/bold] ...")
        # Offensive-by-default discovery: run every stage (docs + JS + fuzz)
        # regardless of early hits (aggressive) and sweep the full SecLists-
        # derived wordlist (deep_fuzz), so protected targets that return few
        # obvious endpoints still get a thorough pass instead of "0 endpoints".
        disc_config = DiscoveryConfig(
            target=target_url,
            scope=scope,
            allow_local_targets=allow_local,
            aggressive=True,
            deep_fuzz=True,
        )
        report = await ApiDiscoveryPipeline(disc_config).run()
        payload = report.to_json()
        endpoints = list(payload.get("endpoints", []))
        access = (payload.get("stats") or {}).get("access") or {}
        if access.get("state") in ("auth_wall", "dead"):
            console.print(
                f"[yellow][!][/yellow] {access.get('reason', access['state'])} "
                f"- 0 endpoints (skipped deep fuzz)."
            )
        else:
            console.print(f"[cyan][*][/cyan] {len(endpoints)} endpoint(s) discovered.")

    # Merge in imported endpoints that fall inside the authorized scope. They
    # are added to the same per-endpoint queue the scanners loop over below
    # (and into the report so BOLA sees them too); out-of-scope ones are
    # dropped (and reported) rather than scanned.
    if imported and imported.endpoints:
        seen = set(endpoints)
        kept = dropped = 0
        for ep in imported.endpoints:
            if not scope.is_in_scope(ep):
                dropped += 1
                continue
            report.add_endpoint(ep, source="traffic_import")
            if ep not in seen:
                endpoints.append(ep)
                seen.add(ep)
                kept += 1
        console.print(
            f"[cyan][*][/cyan] Imported endpoints added to queue: {kept}"
            + (f" ({dropped} out-of-scope, skipped)" if dropped else "")
        )

    # --- Live-asset filtering (Phase 4, HTTPX-style). Before any expensive
    # scanner runs, collapse exact + near-identical endpoints (same route with a
    # different object id) and, optionally, drop endpoints that don't answer a
    # cheap liveness probe. Dedup is always free; the probe is opt-in
    # (--probe-live) and goes through the shared, scope-enforcing HttpEngine. ---
    if endpoints:
        before = len(endpoints)
        lf = filter_live_assets(
            endpoints,
            scope=scope,
            http_engine=http_engine if probe_live else None,
            probe=probe_live,
        )
        endpoints = lf.kept
        if lf.dropped:
            summary = []
            if lf.collapsed:
                summary.append(f"{lf.collapsed} duplicate")
            if lf.out_of_scope:
                summary.append(f"{len(lf.out_of_scope)} out-of-scope")
            if lf.dead:
                summary.append(f"{len(lf.dead)} dead")
            console.print(
                f"[cyan][*][/cyan] Live-asset filter: {before} -> {len(endpoints)} "
                f"target(s) ({', '.join(summary)} dropped)."
            )

    # --- JWT token auto-harvest (default-on, passive, READ-ONLY). When the
    # user did not pass --token, do a bounded GET-only pass over the in-scope
    # endpoints already discovered and pull any JWT the target itself exposes
    # (login response body, Set-Cookie, an echoed auth header, a JS bundle),
    # then seed --token with it so the JWT Tampering module runs automatically.
    # An explicit --token always wins; --no-auto-token opts out. Detection
    # reuses the shared validator in recon/traffic_import (is_valid_jwt), so a
    # dotted non-JWT string is never mistaken for a token. The raw token is
    # never printed - only a redacted alg/length label and the source.
    if not token and auto_token and endpoints:
        try:
            harvested = await asyncio.to_thread(
                harvest_tokens, target_url, endpoints, scope, http_engine
            )
        except Exception as e:  # harvesting must never abort a scan
            harvested = []
            console.print(f"[yellow][!][/yellow] JWT auto-harvest skipped: {e}")
        if harvested:
            token = harvested[0].token
            console.print(
                f"[cyan][*][/cyan] JWT: auto-harvested {redact_jwt(token)} from "
                f"{harvested[0].source} - enabling JWT Tampering checks "
                "(pass --no-auto-token to disable)."
            )
            if len(harvested) > 1:
                console.print(
                    f"[cyan][*][/cyan] JWT: {len(harvested)} token(s) harvested; "
                    "using the first, the rest are available for manual --token."
                )

    # --- Weak HS256 secret (local, bounded, networkless). Run ONCE here (not
    # per endpoint) because a guessable signing secret is a property of the
    # token, not of any one endpoint - otherwise the same finding would repeat
    # for every endpoint the JWT scanner touches. The per-endpoint JWT targets
    # below set check_weak_secret=False so only this central pass emits it.
    if token:
        try:
            secret_result = recover_hs256_secret(token, extra_wordlist=extra_jwt_secrets)
            if secret_result.recovered:
                all_findings.append(
                    build_weak_hs256_finding(target_url, token, secret_result)
                )
                console.print(
                    "[red][!][/red] JWT: HS256 signing secret is WEAK — recovered "
                    f"from a bounded wordlist in {secret_result.attempts} attempt(s) "
                    "(value redacted). This lets anyone forge valid tokens."
                )
        except Exception as e:  # never abort a scan over the local crack
            console.print(f"[yellow][!][/yellow] JWT weak-secret check skipped: {e}")

    # Track which (scanner, asset) pairs ran, so the finding-driven follow-up
    # step never re-runs the same test. Defined before the cloud scanners below
    # so they can register into it too.
    scanned: set[tuple[str, str]] = set()

    # --- Cloud scanners (S3 misconfig, secrets, takeover). These are not tied
    # to the per-endpoint API loop: S3 runs off bucket references, secrets off
    # discovered JS + imported traffic, takeover off discovered hosts. They run
    # even when no API endpoints were found (e.g. a pure bucket-scope scan). ---
    s3_scan_targets: dict[str, tuple] = {}  # asset -> (engine, target) for follow-ups
    # Off-endpoint assets discovery saw the target reference: AWS S3 bucket URLs
    # and the target's own JS bundles. Feeding these in is what makes the S3 and
    # secret / IAM-clue scanners run automatically on a plain `wily scan <domain>`
    # (previously they only fired with --scope-bucket or a traffic import).
    discovered_s3_refs = tuple(sorted(getattr(report, "cloud_assets", set())))
    discovered_js = tuple(
        u for u in sorted(getattr(report, "js_assets", set())) if scope.is_in_scope(u)
    )
    await _run_cloud_scanners(
        all_findings=all_findings,
        scanned=scanned,
        s3_scan_targets=s3_scan_targets,
        endpoints=endpoints,
        imported=imported,
        buckets=buckets,
        root_domain=root_domain,
        scope=scope,
        http_engine=http_engine,
        rate_limiter=rate_limiter,
        allow_local=allow_local,
        confirm_s3_writes=confirm_s3_writes,
        s3_lab_write=s3_lab_write,
        discovered_s3_refs=discovered_s3_refs,
        discovered_js=discovered_js,
        php_shell_confirm=php_shell_confirm,
    )

    # --- Cloud resource enumeration (cloud_enum-style). Opt-in via --cloud-enum:
    # generate candidate names from the target keyword(s) and probe AWS S3 /
    # Azure Blob / GCP for existing/open storage, auto-handing AWS hits to the
    # deep s3_bucket scanner. Keyword-driven, so it runs even with no HTTP
    # endpoints. ---
    #
    # Phase 3 makes it context-aware and budget-safe:
    #   * Seed extraction: mine extra keywords automatically from material the
    #     scan already gathered (endpoint/S3 URLs, imported traffic, and the
    #     org tokens Phase 1 already surfaced in findings) so generation no
    #     longer depends only on --cloud-keyword.
    #   * Auto-trigger: when an AWS signal is observed (amazonaws.com, s3://,
    #     an ARN/IAM clue from Phase 1, or a matching finding) enable the pass
    #     even without --cloud-enum. It stays behind the same per-keyword budget
    #     cap and per-host scope enforcement, and only ever probes names derived
    #     from the authorized target, so scope is never widened.
    cloud_seed_texts: list[str] = [str(ep) for ep in endpoints]
    if imported:
        cloud_seed_texts += list(imported.s3_links) + list(imported.endpoints)
    for f in all_findings:
        cloud_seed_texts.append(str(getattr(f, "asset", "")))
        ev = getattr(f, "evidence", None)
        if isinstance(ev, dict):
            cloud_seed_texts += [v for v in ev.values() if isinstance(v, str)]

    auto_reason: str | None = None
    if not cloud_enum:
        auto_reason = aws_signal_reason(
            findings_categories=[getattr(f, "category", "") for f in all_findings],
            texts=cloud_seed_texts,
        )
        if auto_reason:
            cloud_enum = True

    if cloud_enum:
        # Keep auto-derived seeds small so the per-keyword cap stays a tight
        # overall bound (a handful of extra keywords, never dozens).
        seeds = extract_seeds(domain=root_domain, texts=cloud_seed_texts, max_seeds=6)
        merged_keywords = list(cloud_keywords or [])
        for seed in seeds:
            if seed not in merged_keywords:
                merged_keywords.append(seed)
        if auto_reason:
            console.print(
                f"[cyan][*][/cyan] Cloud enum auto-triggered: {auto_reason}. "
                "Read-only, budget-capped, same scope - pass --no-cloud-enum to "
                "opt out."
            )
        if seeds:
            console.print(
                f"[cyan][*][/cyan] Cloud enum: +{len(seeds)} auto-extracted "
                f"seed keyword(s) ({', '.join(seeds)})."
            )
        await _run_cloud_enum(
            all_findings=all_findings,
            scanned=scanned,
            s3_scan_targets=s3_scan_targets,
            root_domain=root_domain,
            keywords=merged_keywords,
            wordlist_path=cloud_enum_wordlist,
            max_candidates=cloud_enum_max,
            combos=cloud_enum_combos,
            rate_limiter=rate_limiter,
            allow_local=allow_local,
        )

    if not endpoints:
        if not all_findings:
            console.print("[yellow][-][/yellow] No endpoints found, stopping here.")
        _result = _finish(all_findings, output, show_leak, report_formats, feedback_store, ml_model)
        if artifacts_dir:
            _dump_collected(Path(artifacts_dir), report, _result)
        return _result

    # --- SSRF OOB canary: auto-start (default-on) so blind SSRF (level 4) runs
    # without the user passing --blind. Gated on the same confirm_owned_infra
    # that already gates the whole SSRF/IMDS module, so enabling the canary
    # never makes the scan reach further than the SSRF scanner already does.
    # Safety posture is preserved: the canary is a loopback-only listener and
    # the only extra traffic is one read-only outbound fetch the target makes
    # to it per SSRF-candidate parameter - no new destructive or noisy probes.
    # A remote target cannot reach a 127.0.0.1 canary, so this yields real
    # evidence only against local/owned infra; against a remote target it is a
    # harmless no-op (no false blind finding). --blind forces it on even with
    # --no-auto-canary; --no-auto-canary opts out of the automatic start. If
    # the listener cannot bind, we fall back exactly to the pre-auto behavior
    # (no canary, no blind escalation) instead of crashing.
    canary = None
    canary_error: Exception | None = None
    canary_how = ""
    if _want_canary(blind=blind, auto_canary=auto_canary, confirm_owned_infra=confirm_owned_infra):
        canary, canary_error, canary_how = _build_oob_interaction(
            oob_server=oob_server, oob_bind=oob_bind, oob_public_url=oob_public_url
        )
    if canary_error is not None:
        console.print(
            f"[yellow][!][/yellow] OOB interaction backend could not start "
            f"({canary_error}); continuing without blind SSRF / jku / x5u OOB "
            "confirmation."
        )
    if canary:
        trigger = "forced by --blind" if blind else "auto-started"
        console.print(f"[cyan][*][/cyan] OOB interaction {trigger}: {canary_how}")
        # A loopback canary is only reachable by a local target; warn when the
        # target is clearly remote so a silent no-op isn't mistaken for "clean".
        if getattr(canary, "is_loopback", True) and not allow_local:
            console.print(
                "[yellow][!][/yellow] OOB backend is loopback-only; a remote "
                "target cannot reach it. For remote OOB confirmation use "
                "--oob-server <url> or --oob-bind/--oob-public-url."
            )

    try:
        await _scan_endpoints(
            endpoints=endpoints,
            all_findings=all_findings,
            scanned=scanned,
            scope=scope,
            http_engine=http_engine,
            canary=canary,
            token=token,
            yaml_rules=yaml_rules,
            confirm_destructive=confirm_destructive,
            confirm_owned_infra=confirm_owned_infra,
            endpoint_concurrency=endpoint_concurrency,
            deadline=deadline,
        )
    finally:
        if canary:
            canary.stop()

    identities = _parse_identities(identities_raw)
    # Fill BOLA identities from a saved token/session pool file when fewer than
    # two were supplied explicitly. Explicit --identity values always win and
    # keep their slots; the pool only tops up to two, using live-only entries
    # (a cheap read-only GET that returns 200 against the base target). See
    # recon/token_pool.py. Raw tokens are never printed - only a redacted label.
    if token_pool and len(identities) < 2:
        pool = load_token_pool(token_pool)
        taken = {i.name for i in identities}
        candidates = [p for p in pool if p.name not in taken]
        if candidates:
            console.print(
                f"[cyan][*][/cyan] BOLA: token pool has {len(candidates)} candidate "
                "identit(y/ies); checking which are live ..."
            )
            try:
                live = await asyncio.to_thread(
                    select_live_identities,
                    candidates, target_url, http_engine,
                    want=2 - len(identities),
                )
            except Exception as e:  # liveness must never abort a scan
                live = []
                console.print(f"[yellow][!][/yellow] BOLA: token-pool liveness check skipped: {e}")
            for ident in live:
                console.print(f"[cyan][*][/cyan] BOLA: pooled identity '{ident.name}' is live - using it.")
                identities.append(ident)
        elif pool:
            console.print(
                "[yellow][!][/yellow] BOLA: token-pool identities duplicate the "
                "explicit --identity names; nothing to add."
            )

    if len(identities) >= 2:
        console.print(f"[cyan][*][/cyan] BOLA: testing with {len(identities)} identities ...")
        tester = BolaTester(identities=identities, min_confidence="LOW", scope_manager=scope)
        bola_findings = await tester.run(report)
        all_findings += [_bola_to_finding(bf) for bf in bola_findings]
        console.print(f"[cyan][*][/cyan] BOLA: {len(bola_findings)} finding(s).")
        # Record which endpoints the broad pass already covered (every
        # discovery-flagged bola_candidate), so a finding-driven bola follow-up
        # below only runs on authz-bypass endpoints the broad pass skipped.
        for asset in _bola_covered_assets(report):
            scanned.add(("bola", asset))
    elif identities_raw or token_pool:
        console.print(
            "[yellow][!][/yellow] BOLA requires at least two identities "
            "(one identity alone can't be compared) - supply more --identity "
            "values or a --token-pool with >=2 live entries. Skipped."
        )

    # --- Finding-driven follow-ups: run (or recommend) only the deeper tests
    # the detection pass actually justified - see risk/triggers.py. The broad
    # pass above already covered its own (scanner, asset) pairs, so follow-ups
    # that duplicate it are skipped; the value grows as later phases add
    # scanners (S3, API-keys) whose findings trigger new deep tests. ---
    context = TriggerContext(
        has_token=bool(token),
        has_identities=len(identities) >= 2,
        has_canary=False,  # the OOB canary is already stopped here; blind escalation is advised, not auto-run
        has_iam_file=bool(iam_file),
        confirm_s3_writes=confirm_s3_writes,
    )
    followups = derive_followups(all_findings, context)
    await _run_followups(
        followups=followups,
        all_findings=all_findings,
        scanned=scanned,
        scope=scope,
        http_engine=http_engine,
        token=token,
        identities=identities,
        s3_scan_targets=s3_scan_targets,
    )

    _result = _finish(all_findings, output, show_leak, report_formats, feedback_store, ml_model)
    if artifacts_dir:
        _dump_collected(Path(artifacts_dir), report, _result)
    return _result


_BARE_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]")


def _concrete_bucket(ref: str) -> str | None:
    """Resolve a bucket reference (name / s3:// URI / S3 URL) to a concrete
    bucket name, or None for a glob pattern or non-bucket string (a glob like
    'target-*' is a scope filter, not something that can be probed)."""
    name = extract_bucket_name(ref)
    if name:
        return name
    r = (ref or "").strip().lower()
    if "*" in r or "?" in r:
        return None
    return r if _BARE_BUCKET_RE.fullmatch(r) else None


def _s3_object_key(ref: str) -> str | None:
    """Best-effort object key from an s3:// URI or an S3 URL path."""
    if not isinstance(ref, str):
        return None
    v = ref.strip()
    if v.lower().startswith("s3://"):
        rest = v[5:].split("?", 1)[0]
        parts = rest.split("/", 1)
        return parts[1] if len(parts) == 2 and parts[1] else None
    if "amazonaws.com" in v.lower():
        parsed = urlparse(v if "://" in v else "//" + v)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lstrip("/")
        if not path:
            return None
        first_label = host.split(".", 1)[0]
        # Virtual-hosted host is "<bucket>.s3...": the whole path is the key.
        # Path-style host is "s3...": the first path segment is the bucket, the
        # remainder is the key.
        if first_label and first_label != "s3" and not first_label.startswith("s3-"):
            return path or None
        parts = path.split("/", 1)
        return parts[1] if len(parts) == 2 and parts[1] else None
    return None


def _build_s3_engine(
    bucket: str, region: str | None, allow_local: bool, rate_limiter
) -> HttpEngine | None:
    """An HttpEngine scoped to the bucket's S3 host. S3 endpoints are public,
    so the engine's own scope guard permits them while still refusing any
    non-S3 host; returns None if the host is not a usable scope target."""
    host = s3_host_for(bucket, region)
    try:
        s3_scope = ScopeManager(host, allow_local_targets=allow_local)
    except ScopeError:
        return None
    return HttpEngine(scope_manager=s3_scope, rate_limiter=rate_limiter)


def _cname_resolver(host: str) -> str | None:
    """Best-effort CNAME lookup via the stdlib (no extra dependency). The alias
    list from ``gethostbyname_ex`` carries the CNAME chain; the last alias is
    the closest-to-target canonical name. Returns None on any failure."""
    import socket

    try:
        _name, aliases, _ips = socket.gethostbyname_ex(host)
    except Exception:
        return None
    return aliases[-1] if aliases else None


@dataclass
class OptionalProbes:
    """Inputs for the opt-in, single-URL scanners that need a tester-supplied
    target and so cannot run on a plain domain sweep (same category as BOLA).

    Each is enabled only when its primary field is set; passing the flag IS the
    explicit opt-in, so the active-probe confirmations (timing / token entropy)
    are taken as granted. They run ONCE per invocation (not per subdomain), and
    their findings are folded into the primary report.
    """

    # session_fixation (OWASP A07): does the session cookie survive login?
    session_fixation_login: str | None = None
    session_fixation_submit: str | None = None
    session_fixation_body: str = ""
    # timing_enum: account enumeration via a login-timing side channel.
    timing_url: str | None = None
    timing_invalid_users: tuple[str, ...] = ()
    timing_candidate_users: tuple[str, ...] = ()
    # token_entropy: statistical weakness in issued session/CSRF tokens.
    token_entropy_url: str | None = None
    token_entropy_cookie: str | None = None
    token_entropy_pattern: str | None = None
    # stage_inconsistency: a non-prod API Gateway stage left unprotected.
    stage_template: str | None = None

    def any_enabled(self) -> bool:
        return bool(
            self.session_fixation_login
            or self.timing_url
            or self.token_entropy_url
            or self.stage_template
        )


def _probe_engine(url: str, allow_local: bool) -> tuple[ScopeManager, HttpEngine]:
    """A fresh scope+engine authorized for the probe URL's host. The user
    supplying the URL is the authorization; the engine still enforces it."""
    host = urlparse(url).hostname or url
    scope = ScopeManager(host, allow_local_targets=allow_local)
    return scope, HttpEngine(scope_manager=scope)


async def _run_optional_probes(probes: OptionalProbes, *, allow_local: bool) -> list:
    """Run each configured opt-in probe once and return the pooled findings.

    Every probe is isolated in its own try/except so one bad input never aborts
    the others or the surrounding scan.
    """
    findings: list = []
    if not probes.any_enabled():
        return findings

    if probes.session_fixation_login:
        _scope, engine = _probe_engine(probes.session_fixation_login, allow_local)
        try:
            findings += await run_scanner(
                SessionFixationScanner(http_engine=engine),
                SessionFixationTarget(
                    login_page_url=probes.session_fixation_login,
                    login_submit_url=(
                        probes.session_fixation_submit or probes.session_fixation_login
                    ),
                    credentials_body=probes.session_fixation_body,
                ),
            )
            console.print("[cyan]    [*][/cyan] Session-fixation probe ran.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Session-fixation probe failed: {e}")

    if probes.timing_url:
        _scope, engine = _probe_engine(probes.timing_url, allow_local)
        try:
            findings += await run_scanner(
                TimingEnumScanner(http_engine=engine, confirm_timing_probe=True),
                TimingEnumTarget(
                    url=probes.timing_url,
                    known_invalid_users=list(probes.timing_invalid_users),
                    candidate_users=list(probes.timing_candidate_users),
                ),
            )
            console.print("[cyan]    [*][/cyan] Timing-enumeration probe ran.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Timing-enumeration probe failed: {e}")

    if probes.token_entropy_url:
        _scope, engine = _probe_engine(probes.token_entropy_url, allow_local)
        try:
            findings += await run_scanner(
                TokenEntropyScanner(http_engine=engine, confirm_deep_analysis=True),
                TokenEntropyTarget(
                    url=probes.token_entropy_url,
                    cookie_name=probes.token_entropy_cookie,
                    body_pattern=probes.token_entropy_pattern,
                ),
            )
            console.print("[cyan]    [*][/cyan] Token-entropy probe ran.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Token-entropy probe failed: {e}")

    if probes.stage_template:
        baseline_url = probes.stage_template.replace("{stage}", "prod")
        scope, engine = _probe_engine(baseline_url, allow_local)
        try:
            findings += await run_scanner(
                StageInconsistencyScanner(scope_manager=scope, http_engine=engine),
                StageInconsistencyTarget(url_template=probes.stage_template),
            )
            console.print("[cyan]    [*][/cyan] Stage-inconsistency probe ran.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Stage-inconsistency probe failed: {e}")

    return findings


async def _run_cloud_scanners(
    *,
    all_findings: list,
    scanned: set,
    s3_scan_targets: dict,
    endpoints: list[str],
    imported: ImportedTraffic | None,
    buckets: tuple[str, ...],
    root_domain: str,
    scope: ScopeManager,
    http_engine: HttpEngine,
    rate_limiter,
    allow_local: bool,
    confirm_s3_writes: bool,
    s3_lab_write: bool = False,
    discovered_s3_refs: tuple[str, ...] = (),
    discovered_js: tuple[str, ...] = (),
    php_shell_confirm: bool = False,
) -> None:
    """Run the Phase 3 cloud scanners and fold their findings into the run.

    Each scanner is isolated in its own try/except so a failure in one (or a
    single bad target) never aborts the scan.

    ``discovered_s3_refs`` / ``discovered_js`` are off-endpoint assets the
    discovery pass saw the target reference (bucket URLs and JS bundles). They
    are what makes the S3 and secret / IAM-clue scanners fire automatically on a
    plain domain scan, instead of only with --scope-bucket or an import.
    """
    # ---- S3 bucket misconfiguration ------------------------------------
    # Candidate references: explicit bucket scope + imported s3 links + any S3
    # URLs among endpoints + bucket URLs discovery saw in the page/JS.
    # Deduplicated by concrete bucket name.
    s3_refs: list[str] = list(buckets)
    if imported and imported.s3_links:
        s3_refs += imported.s3_links
    s3_refs += [ep for ep in endpoints if extract_bucket_name(ep)]
    s3_refs += list(discovered_s3_refs)

    seen_buckets: set[str] = set()
    for ref in s3_refs:
        bucket = _concrete_bucket(ref)
        if not bucket or bucket in seen_buckets:
            continue
        seen_buckets.add(bucket)
        # Respect bucket scope when configured.
        if scope.has_bucket_scope and not scope.is_bucket_in_scope(ref):
            console.print(f"[yellow]    [!][/yellow] S3 bucket out of scope, skipped: {bucket}")
            continue
        engine = _build_s3_engine(bucket, None, allow_local, rate_limiter)
        if engine is None:
            continue
        target = S3BucketTarget(bucket=bucket, sample_object_key=_s3_object_key(ref))
        try:
            found = await run_scanner(
                # lab_write forwards the --s3-lab-write flag; the scanner still
                # refuses the active PUT/DELETE unless WILY_ALLOW_S3_WRITE=true
                # AND the bucket is inside the configured owned/lab scope, so
                # passing the shared `scope` (which carries the bucket scope) is
                # what actually enables it. Default off => read-only as before.
                S3BucketScanner(
                    scope_manager=scope,
                    http_engine=engine,
                    confirm_writes=False,
                    lab_write=s3_lab_write,
                ),
                target,
            )
            all_findings += found
            scanned.add(("s3_bucket", f"s3://{bucket}"))
            # Stash for a possible write-permission follow-up (keyed by the
            # finding asset, which is "s3://<bucket>").
            s3_scan_targets[f"s3://{bucket}"] = (engine, target)
            if found:
                console.print(f"[cyan]    [*][/cyan] S3 {bucket}: {len(found)} finding(s).")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] S3 scan failed for {bucket}: {e}")

    # ---- Secrets / API-key exposure ------------------------------------
    secret_sources: list[SecretSource] = []
    # Observed auth tokens from an imported capture are themselves exposed
    # credentials; wrap each so the detector sees an Authorization context.
    for tok in (imported.tokens if imported else []):
        secret_sources.append(
            SecretSource(
                label="imported-traffic-token",
                content=f"Authorization: Bearer {tok}",
                location="imported-traffic",
            )
        )
    # Discovered JS bundles are the prime place hardcoded keys leak; fetch the
    # in-scope ones and scan their bodies.
    js_urls = [
        ep for ep in endpoints
        if urlparse(ep).path.lower().endswith(".js") and scope.is_in_scope(ep)
    ]
    # JS bundles discovery referenced but did not emit as endpoints (their URL
    # is dropped as a non-API static asset); fetch them here for secret/IAM
    # scanning. Scope is still enforced by the scanner's own engine.
    for u in discovered_js:
        if scope.is_in_scope(u) and u not in js_urls:
            js_urls.append(u)
    if secret_sources or js_urls:
        try:
            found = await run_scanner(
                SecretScanScanner(scope_manager=scope, http_engine=http_engine),
                SecretScanTarget(sources=secret_sources, fetch_urls=js_urls),
            )
            all_findings += found
            scanned.add(("secret_scan", root_domain))
            if found:
                console.print(
                    f"[cyan]    [*][/cyan] Secret scan: {len(found)} exposed secret(s) "
                    f"across {len(secret_sources)} source(s) + {len(js_urls)} JS file(s)."
                )
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Secret scan failed: {e}")

    # ---- IAM / ARN clue extraction (Phase 1) ---------------------------
    # Same corpus as the secret scan (imported-traffic text + discovered JS),
    # plus any accidentally-exposed IaC files discovery turned up. Surfaces
    # AWS *identifiers* (ARNs, role names, AssumeRole snippets, account ids) -
    # informational on their own; the trigger layer escalates them to an
    # iam_privesc follow-up when an --iam-file was supplied.
    iam_clue_sources = [
        IamClueSource(label=s.label, content=s.content, location=s.location)
        for s in secret_sources
    ]
    iac_urls = [
        ep for ep in endpoints
        if looks_like_iac(urlparse(ep).path) and scope.is_in_scope(ep)
    ]
    iam_clue_fetch = js_urls + iac_urls
    if iam_clue_sources or iam_clue_fetch:
        try:
            found = await run_scanner(
                IamClueScanner(scope_manager=scope, http_engine=http_engine),
                IamClueTarget(sources=iam_clue_sources, fetch_urls=iam_clue_fetch),
            )
            all_findings += found
            scanned.add(("iam_clue_scan", root_domain))
            if found:
                console.print(
                    f"[cyan]    [*][/cyan] IAM clue scan: {len(found)} clue(s) "
                    f"across {len(iam_clue_sources)} source(s) + "
                    f"{len(js_urls)} JS + {len(iac_urls)} IaC file(s)."
                )
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] IAM clue scan failed: {e}")

    # ---- Subdomain / resource takeover ---------------------------------
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for candidate in [root_domain] + [urlparse(ep).hostname or "" for ep in endpoints]:
        h = (candidate or "").strip().lower()
        if not h or h in seen_hosts or not scope.is_in_scope(h):
            continue
        seen_hosts.add(h)
        hosts.append(h)
    for host in hosts:
        try:
            found = await run_scanner(
                TakeoverScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    resolver=_cname_resolver,
                ),
                TakeoverTarget(host=host),
            )
            all_findings += found
            scanned.add(("takeover", host))
            if found:
                console.print(f"[cyan]    [*][/cyan] Takeover indicator on {host}: {len(found)}.")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] Takeover scan failed for {host}: {e}")

    # ---- TLS/SSL configuration (always-on, read-only) ------------------
    # A TLS handshake is as safe as a GET and needs no input beyond the host,
    # so it runs automatically on every in-scope host. Skipped for --allow-local
    # targets (the scanner refuses private/loopback addresses anyway).
    if not allow_local:
        for host in hosts:
            try:
                found = await run_scanner(
                    TlsConfigScanner(scope_manager=scope),
                    TlsConfigTarget(host=host),
                )
                all_findings += found
                scanned.add(("tls_config", host))
                if found:
                    console.print(f"[cyan]    [*][/cyan] TLS config on {host}: {len(found)} finding(s).")
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] TLS config scan failed for {host}: {e}")

    # ---- php2shell / PHP-to-shell exposure (always-on, SAFE detection) -----
    # The automatic path is non-destructive: it reads the PHP version banner
    # the server advertises (a single GET) and does a GET presence check for
    # the classic eval-stdin.php PHP-to-shell path. It NEVER triggers the
    # memory-corruption / use-after-free bug. The opt-in active behavioral
    # confirmation (--php-shell-confirm) is gated and default-off; it is never
    # reachable without that flag.
    php_scheme = "http" if allow_local else "https"
    for host in hosts:
        try:
            found = await run_scanner(
                PhpShellScanner(
                    scope_manager=scope,
                    http_engine=http_engine,
                    confirm_exploit=php_shell_confirm,
                ),
                PhpShellTarget(
                    url=f"{php_scheme}://{host}",
                    attempt_active_confirmation=php_shell_confirm,
                ),
            )
            all_findings += found
            scanned.add(("php_shell", host))
            if found:
                console.print(f"[cyan]    [*][/cyan] php2shell exposure on {host}: {len(found)} finding(s).")
        except ScannerConfirmationError as e:
            console.print(f"[yellow]    [!][/yellow] php2shell active check skipped: {e}")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] php2shell scan failed for {host}: {e}")


def _provider_engine_factory(allow_local: bool, rate_limiter, timeout: float = 10.0):
    """Return ``factory(host) -> HttpEngine`` that builds (and caches) one
    scope-to-that-host engine per provider host. Each engine's own ScopeManager
    permits only its single public cloud host; a host that is not a valid scope
    target yields None (the scanner then skips that provider).

    ``timeout`` is overridable (default matches ``HttpEngine``'s own default):
    cloud-enum candidates are overwhelmingly nonexistent names, where the cost
    is a slow DNS/connect failure rather than a slow response from a real
    endpoint - a shorter timeout there cuts worst-case latency without losing
    true positives, which reply almost immediately.
    """
    cache: dict[str, HttpEngine | None] = {}

    def factory(host: str):
        if host in cache:
            return cache[host]
        try:
            eng = HttpEngine(
                scope_manager=ScopeManager(host, allow_local_targets=allow_local),
                rate_limiter=rate_limiter,
                timeout=timeout,
            )
        except ScopeError:
            eng = None
        cache[host] = eng
        return eng

    return factory


async def _run_cloud_enum(
    *,
    all_findings: list,
    scanned: set,
    s3_scan_targets: dict,
    root_domain: str,
    keywords: list[str],
    wordlist_path: str | None,
    max_candidates: int | None,
    rate_limiter,
    allow_local: bool,
    combos: bool = False,
) -> None:
    """Generate candidate names from keyword(s) and probe AWS/Azure/GCP storage.

    AWS hits are handed to the deep ``s3_bucket`` scanner (the "auto -> S3
    scanner" flow); Azure and GCP hits are reported directly. All probes are
    read-only GETs through per-host, scope-enforcing engines.
    """
    kws = [k for k in keywords if k.strip()]
    derived = keyword_from_domain(root_domain)
    if derived and derived not in kws:
        kws.append(derived)
    if not kws:
        console.print("[yellow][!][/yellow] Cloud enum: no usable keyword, skipped.")
        return

    mutations = None
    if wordlist_path:
        try:
            mutations = load_mutations(wordlist_path)
        except OSError as e:
            console.print(f"[yellow][!][/yellow] Cloud enum wordlist ignored: {e}")

    cap = _cloud_enum_cap(max_candidates, combos, len(kws))
    candidates = generate_candidates(kws, mutations, max_candidates=cap, combos=combos)
    total = len(generate_candidates(kws, mutations, combos=combos))
    console.print(
        f"[cyan][*][/cyan] Cloud enum: {len(candidates)} candidate name(s) from "
        f"keyword(s) {', '.join(kws)} (AWS/Azure/GCP"
        + (", with three-part combos" if combos else "")
        + ")."
    )
    if total > len(candidates):
        console.print(
            f"[yellow][!][/yellow] Cloud enum: capped at {len(candidates)} of {total} "
            "generated names - raise --cloud-enum-max to probe the rest."
        )

    # A short per-request timeout: a real bucket/account replies almost
    # instantly, so the only thing a long timeout buys here is a slower
    # failure for the (overwhelming majority of) names that don't exist.
    factory = _provider_engine_factory(allow_local, rate_limiter, timeout=5.0)
    enum_scanner = CloudStorageScanner(engine_factory=factory)
    aws_hits: set[str] = set()

    # Bounded concurrency, higher than the discovery pipeline's default (15):
    # candidates are independent per-host probes across three separate cloud
    # providers, not many requests against one target, so there is no shared
    # host to overload by running more of them at once. Running them
    # one-at-a-time previously serialized the ENTIRE cap (up to 400+ names x a
    # ~10s timeout each - tens of minutes) for no safety reason.
    _sem = asyncio.Semaphore(40)

    async def _probe_one(name: str) -> None:
        nonlocal all_findings
        async with _sem:
            target = CloudStorageTarget(name=name, azure_account=azure_account_name(name))
            try:
                found = await run_scanner(enum_scanner, target)
            except Exception as e:
                console.print(f"[yellow]    [!][/yellow] Cloud enum failed for {name}: {e}")
                return
        if not found:
            return
        all_findings += found
        scanned.add(("cloud_storage_enum", name))
        for f in found:
            if f.evidence.get("provider") == "aws":
                aws_hits.add(f.evidence.get("bucket") or name)
            console.print(
                f"[cyan]    [*][/cyan] {f.category}: {f.asset}"
            )

    await asyncio.gather(*(_probe_one(name) for name in candidates))

    # Auto hand-off: run the deep S3 scanner on every existing AWS bucket found.
    for bucket in sorted(aws_hits):
        asset = f"s3://{bucket}"
        if ("s3_bucket", asset) in scanned:
            continue
        engine = _build_s3_engine(bucket, None, allow_local, rate_limiter)
        if engine is None:
            continue
        s3_target = S3BucketTarget(bucket=bucket)
        try:
            deep = await run_scanner(
                S3BucketScanner(http_engine=engine, confirm_writes=False), s3_target
            )
            all_findings += deep
            scanned.add(("s3_bucket", asset))
            s3_scan_targets[asset] = (engine, s3_target)
            if deep:
                console.print(
                    f"[cyan]    [>][/cyan] s3_bucket deep scan on {bucket}: {len(deep)} finding(s)."
                )
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] s3_bucket deep scan failed for {bucket}: {e}")


def _bola_covered_assets(report) -> set[str]:
    """Endpoints the broad BOLA pass already tested: every discovery-flagged
    ``bola_candidate`` in the report. Returned as a set of (scanner-side) asset
    keys so a bola follow-up on one of them is skipped as a duplicate."""
    covered: set[str] = set()
    for url, record in getattr(report, "endpoints", {}).items():
        if (getattr(record, "details", None) or {}).get("bola_candidate"):
            covered.add(url)
    return covered


async def _run_followups(
    *,
    followups: list,
    all_findings: list,
    scanned: set,
    scope,
    http_engine,
    token: str | None,
    identities: list,
    s3_scan_targets: dict,
) -> None:
    """Execute every finding-driven follow-up that has a concrete, safe run
    path, and surface the rest as a justified next step.

    Auto-run here:
      - ``jwt_tamper``: deep JWT tampering on an endpoint with broken authz.
      - ``bola``: cross-tenant replay on an authz-bypass endpoint the broad
        BOLA pass did not already cover (broken authz is itself a strong BOLA
        signal, even when discovery never flagged the endpoint a candidate).
        Read-only (GET replay); needs >= 2 identities.
      - ``s3_permcheck``: the deeper S3 step - re-run the bucket with
        ``confirm_writes=True`` so the read-only, ACL-derived write/delete
        check runs now that a public finding justified it.

    Recommended (not auto-run): ``ssrf_blind`` (the OOB canary is already
    stopped, and blind SSRF ran inline with it during detection) and
    ``iam_privesc`` (the supplied IAM file was already analyzed; using the
    leaked credentials for live enumeration is a separate, manual step).
    """
    pending = [fu for fu in followups if (fu.scanner, fu.asset) not in scanned]
    if not pending:
        return
    console.print(f"\n[cyan][*][/cyan] Finding-driven follow-ups: {len(pending)}")
    for fu in pending:
        try:
            if fu.scanner == "jwt_tamper" and token:
                all_findings += await run_scanner(
                    JwtTamperScanner(scope_manager=scope, http_engine=http_engine),
                    JwtTarget(url=fu.asset, sample_token=token, check_weak_secret=False),
                )
                scanned.add((fu.scanner, fu.asset))
                console.print(f"[cyan]    [>][/cyan] ran {fu.scanner} on {fu.asset} — {fu.reason}")
            elif fu.scanner == "bola" and len(identities) >= 2:
                # Minimal one-endpoint report, flagged a candidate, so the
                # broken-authz endpoint is replayed across identities even
                # though discovery never marked it.
                mini = DiscoveryReport(target=fu.asset)
                mini.add_endpoint(
                    fu.asset, source="followup", methods=["GET"],
                    details={"bola_candidate": True},
                )
                tester = BolaTester(
                    identities=identities, min_confidence="LOW", scope_manager=scope
                )
                bola_findings = await tester.run(mini)
                all_findings += [_bola_to_finding(bf) for bf in bola_findings]
                scanned.add((fu.scanner, fu.asset))
                console.print(f"[cyan]    [>][/cyan] ran bola on {fu.asset} — {fu.reason}")
            elif fu.scanner == "s3_permcheck" and fu.asset in s3_scan_targets:
                engine, s3_target = s3_scan_targets[fu.asset]
                all_findings += await run_scanner(
                    S3BucketScanner(
                        scope_manager=scope, http_engine=engine, confirm_writes=True
                    ),
                    s3_target,
                )
                scanned.add((fu.scanner, fu.asset))
                console.print(f"[cyan]    [>][/cyan] ran s3 permission-check on {fu.asset} — {fu.reason}")
            else:
                # No safe standalone run path here - surface it as a justified
                # next step for the analyst.
                console.print(f"[cyan]    [>][/cyan] recommend {fu.scanner} on {fu.asset} — {fu.reason}")
        except Exception as e:
            console.print(f"[yellow]    [!][/yellow] follow-up {fu.scanner} failed: {e}")


_BOLA_CONFIDENCE_TO_FLOAT = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.4}
_BOLA_CONFIDENCE_TO_SEVERITY = {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}


def _bola_to_finding(bf) -> Finding:
    """BolaFinding has a different schema from the shared Finding type
    (confidence is a string like HIGH/MEDIUM/LOW, no separate severity) -
    converted here so the unified report stays consistent with every
    other module."""
    return Finding(
        asset=bf.endpoint,
        category="bola-cross-tenant-access",
        severity=_BOLA_CONFIDENCE_TO_SEVERITY.get(bf.confidence, "medium"),
        confidence=_BOLA_CONFIDENCE_TO_FLOAT.get(bf.confidence, 0.5),
        evidence={
            "owner_identity": bf.owner_identity,
            "tester_identity": bf.tester_identity,
            "json_similarity": bf.json_similarity,
            "grounding": bf.grounding,
            "notes": bf.notes,
        },
        discovery_source="scanner",
        remediation=(
            "Actually verify resource ownership before returning data "
            "(match the identity extracted from the session against the "
            "resource's owner), not just that the JWT/session is valid."
        ),
    )


def _parse_identities(raw: list[str]) -> list[Identity]:
    """Each --identity is name=HeaderValue (e.g. tenant_a='Bearer xyz')."""
    identities = []
    for item in raw:
        if "=" not in item:
            continue
        name, _, header_value = item.partition("=")
        identities.append(Identity(name=name, headers={"Authorization": header_value}))
    return identities


_VALID_FORMATS = ("json", "html", "sarif")

# Each writer takes (findings, path, redact=..., preserve_order=...) and the
# extension its output path should carry.
_FORMAT_WRITERS = {
    "json": (export_json, ".json"),
    "html": (export_html, ".html"),
    "sarif": (export_sarif, ".sarif"),
}


def parse_report_formats(raw: list[str] | None) -> list[str]:
    """Normalize --format values (repeatable and/or comma-separated) into an
    ordered, de-duplicated list of known formats. Unknown tokens are dropped
    with a warning; JSON is always included so the default report never
    vanishes."""
    formats: list[str] = []
    for item in raw or []:
        for token in str(item).split(","):
            name = token.strip().lower()
            if not name:
                continue
            if name not in _VALID_FORMATS:
                console.print(f"[yellow][!][/yellow] Unknown --format '{name}', ignored.")
                continue
            if name not in formats:
                formats.append(name)
    if "json" not in formats:
        formats.insert(0, "json")
    return formats


def _report_path(output: Path, fmt: str) -> Path:
    """Where format ``fmt`` is written relative to the user's -o path.

    The requested path keeps its exact name for the format that matches its
    suffix (so JSON stays at ``wily-report.json``); other formats are written
    as siblings with the format's own extension.
    """
    _writer, ext = _FORMAT_WRITERS[fmt]
    if output.suffix.lower() == ext:
        return output
    # Strip a known report extension before appending the new one, so
    # "wily-report.json" + html -> "wily-report.html", not ".json.html".
    stem = output
    if output.suffix.lower() in (".json", ".html", ".sarif"):
        stem = output.with_suffix("")
    return stem.with_name(stem.name + ext)


def _write_reports(
    findings: list, output: str, show_leak: bool, report_formats: list[str] | None
) -> None:
    formats = parse_report_formats(report_formats)
    base = Path(output)
    for fmt in formats:
        writer, _ext = _FORMAT_WRITERS[fmt]
        path = _report_path(base, fmt)
        writer(findings, path, redact=not show_leak, preserve_order=True)
        console.print(f"[green][+][/green] {fmt.upper()} report: {path.resolve()}")


def _finish(
    findings: list,
    output: str,
    show_leak: bool = False,
    report_formats: list[str] | None = None,
    feedback_store: str | None = None,
    ml_model: str | None = None,
) -> list:
    # Correlation/dedup pass before anything is displayed or written, so the
    # console summary and the report agree and neither shows the same issue
    # twice. In order:
    #   1. exact-duplicate collapse (deterministic rules),
    #   2. near-duplicate clustering on the SAME asset (risk/ml/dedup.deduplicate),
    #   3. endpoint-hash clustering across DIFFERENT assets that normalize to
    #      the same shape (risk/ml/dedup.cluster_by_endpoint_hash),
    #   4. annotate with any prior analyst --valid/--fp decision, if a
    #      feedback store was given (risk/ml/feedback - opt-in, informational
    #      only: it never drops or reorders a finding), then
    #   5. ranking/prioritisation (risk/ml/ranker) - the single source of the
    #      order the table and the JSON report both use.
    findings = apply_deterministic_rules(findings)
    findings = deduplicate(findings)
    findings = cluster_by_endpoint_hash(findings)
    if feedback_store:
        findings = FeedbackStore(feedback_store).apply(findings)

    # Optional trained-model re-ranking (opt-in via --ml-model). When no model
    # is given, rank_findings runs heuristic-only, exactly as before. A model
    # that fails to load degrades to heuristics with a warning - it never
    # aborts the scan - and the model can only re-rank/annotate, never drop a
    # finding.
    triage_model = None
    if ml_model:
        triage_model, reason = load_triage_model(ml_model)
        if triage_model is None:
            console.print(
                f"[yellow][!][/yellow] --ml-model ignored ({reason}); "
                "falling back to heuristic ranking."
            )
        else:
            console.print(
                f"[cyan][*][/cyan] ML triage model enabled ({ml_model}); "
                "findings re-ranked + annotated with evidence['ml_valid_probability']."
            )
    findings = rank_findings(findings, model=triage_model)

    console.print(f"\n[green][+][/green] Total findings: {len(findings)}\n")
    if findings:
        table = Table(title="All findings (highest risk first)")
        table.add_column("Risk", justify="right")
        table.add_column("Category", style="red")
        table.add_column("Asset", overflow="fold")
        table.add_column("Severity")
        for f in findings:
            risk = compute_risk_score(f.severity, f.confidence)
            table.add_row(f"{risk:.1f}", f.category, str(f.asset), f.severity)
        console.print(table)

    if show_leak:
        console.print(
            "[yellow][!][/yellow] --show-leak: evidence written UNREDACTED "
            "(captured secrets are visible in the report)."
        )
    _write_reports(findings, output, show_leak, report_formats)
    return findings
