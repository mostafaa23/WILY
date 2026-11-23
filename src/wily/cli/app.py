"""Main entry point for the Typer app.

After `pip install .` (or `pip install -e .` during development), this
command is available directly in any terminal as `wily`:

    wily --help
    wily scan example.com                          # the full bundle, automatic
    wily scan a.com b.com --output-dir reports/     # several domains, one report each
    wily scan --targets-file targets.txt --output-dir reports/  # targets from a file
    wily scan example.com --token JWT_VALUE         # + JWT
    wily scan example.com --identity a=Bearer-x --identity b=Bearer-y  # + BOLA
    wily scan example.com --iam-file auth.json      # + IAM
    wily scan example.com --blind                   # + SSRF level 4
    wily scan example.com --confirm-destructive      # + write-method authz probes
    wily scan example.com --confirm-owned-infra      # + SSRF/IMDS checks

    wily jwt <url> --token TOKEN_VALUE              # a single, focused module
    wily authz <url>
    wily ssrf <url> --param url
    wily iam <authorization-details.json>
    wily discover <domain>
    wily triage <report.json> --valid 2 --fp 5   # feedback loop
"""

import asyncio
import logging

import typer

from wily import __version__
from wily.cli.banner import print_banner
from wily.cli.commands import (
    authz_cmd,
    discover_cmd,
    iam_cmd,
    jwt_cmd,
    scan_all,
    ssrf_cmd,
    templates_cmd,
    triage_cmd,
)
from wily.cli.gate import FailOn, evaluate_gate, format_gate_lines

logger = logging.getLogger("wily.cli")

app = typer.Typer(
    name="wily",
    help=(
        "Cloud-native, black-box API security scanner.\n\n"
        "Discovers a target's real endpoints, routes each one to the right "
        "checks (Auth Bypass, CORS, SSRF, JWT, BOLA, IAM), triages the "
        "findings by real evidence, and writes unified JSON / HTML / SARIF "
        "reports. 'scan' runs the whole bundle automatically; the other "
        "commands run a single module on its own."
    ),
    add_completion=True,
    # The callback (invoke_without_command=True) prints the banner and then the
    # help on a bare ``wily``, so we must NOT let Typer short-circuit to help
    # before the callback runs.
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.command("scan")
def scan_command(
    domains: list[str] = typer.Argument(
        None,
        metavar="[DOMAINS]...",
        help=(
            "One or more target domains (e.g. example.com a.com b.com). Each "
            "domain gets its OWN report - never a merged one. With two or more "
            "targets, pass --output-dir to say where the per-domain reports go. "
            "Leave empty if using --iam-file/--burp-xml/--import-har alone."
        ),
    ),
    targets_file: str = typer.Option(
        None, "--targets-file",
        help=(
            "Path to a text file of target domains, one per line. Blank lines and "
            "lines starting with '#' are ignored. Combined with any positional "
            "domains and de-duplicated."
        ),
    ),
    token: str = typer.Option(None, "--token", "-t", help="A valid JWT - enables JWT Tampering checks."),
    identity: list[str] = typer.Option(
        None, "--identity",
        help="name=HeaderValue (e.g. tenant_a='Bearer xyz'). Repeat at least twice to enable BOLA.",
    ),
    iam_file: str = typer.Option(
        None, "--iam-file", help="Path to the output of: aws iam get-account-authorization-details - enables IAM checks."
    ),
    allow_local: bool = typer.Option(False, "--allow-local", help="Allow scanning 127.0.0.1/localhost (local testing only)."),
    blind: bool = typer.Option(False, "--blind", help="Force-enable Blind SSRF checks via a local OOB canary (level 4). On by default via auto-canary; this forces it even with --no-auto-canary."),
    auto_token: bool = typer.Option(
        True, "--auto-token/--no-auto-token",
        help=(
            "Auto-harvest a JWT the target exposes (login body, Set-Cookie, "
            "echoed header, JS bundle) and run the JWT Tampering checks with "
            "it - no --token needed. ON by default (passive, read-only, "
            "GET-only). An explicit --token always wins; --no-auto-token opts "
            "out. The harvested token is never printed (redacted in output)."
        ),
    ),
    auto_canary: bool = typer.Option(
        True, "--auto-canary/--no-auto-canary",
        help=(
            "Auto-start the local OOB canary so Blind SSRF (level 4) runs "
            "without --blind, when it can bind a local listener. ON by default; "
            "gated on --confirm-owned-infra like the rest of SSRF, and falls "
            "back cleanly if the listener can't start. --no-auto-canary opts "
            "out (--blind still forces it on)."
        ),
    ),
    confirm_destructive: bool = typer.Option(
        True, "--confirm-destructive/--no-destructive",
        help=(
            "Probe write methods (POST/PUT/DELETE/PATCH) in the Auth Bypass "
            "check. ON by default (offensive). These requests can create, "
            "modify, or delete real data on the target - pass --no-destructive "
            "to restrict to safe read methods only."
        ),
    ),
    confirm_owned_infra: bool = typer.Option(
        True, "--confirm-owned-infra/--no-owned-infra",
        help=(
            "Run the SSRF/IMDS check. ON by default (offensive). This check "
            "makes the target fetch internal metadata endpoints on your "
            "behalf - pass --no-owned-infra to skip it."
        ),
    ),
    confirm_s3_writes: bool = typer.Option(
        False, "--confirm-s3-writes/--no-s3-writes",
        help=(
            "Report S3 write/delete exposure. OFF by default (safe). Even when "
            "on, Wily only READS the bucket ACL/policy and infers writability "
            "from a public WRITE grant - it never sends a PUT/DELETE, so it "
            "cannot overwrite or delete objects on any target."
        ),
    ),
    use_rules: bool = typer.Option(
        False, "--rules/--no-rules",
        help=(
            "Also run the declarative YAML rules (src/wily/templates/rules) "
            "alongside the code scanners. OFF by default; see "
            "`wily templates list` for the loaded rules. Read-only, and "
            "findings dedupe against the equivalent code scanners."
        ),
    ),
    probe_live: bool = typer.Option(
        False, "--probe-live/--no-probe-live",
        help=(
            "Before scanning, drop discovered/imported endpoints that don't "
            "answer a cheap HEAD/GET liveness probe. OFF by default; "
            "de-duplication of near-identical URLs always runs regardless. The "
            "probe goes through the shared, scope-enforced HTTP engine."
        ),
    ),
    cloud_enum: bool = typer.Option(
        False, "--cloud-enum/--no-cloud-enum",
        help=(
            "Enumerate cloud storage (AWS S3 / Azure Blob / GCP) by generating "
            "candidate bucket names from the target keyword(s) and mutations "
            "(cloud_enum-style), then probing each - read-only. Existing AWS "
            "buckets are auto-handed to the deep s3_bucket scan. OFF by default."
        ),
    ),
    cloud_keyword: list[str] = typer.Option(
        None, "--cloud-keyword",
        help=(
            "Extra keyword(s) to seed cloud-enum name generation (repeatable). "
            "The target's own name is derived from the domain automatically."
        ),
    ),
    cloud_enum_wordlist: str = typer.Option(
        None, "--cloud-enum-wordlist",
        help=(
            "Path to a mutations wordlist (one per line, e.g. cloud_enum's "
            "fuzz.txt) replacing the built-in default list."
        ),
    ),
    cloud_enum_max: int = typer.Option(
        300, "--cloud-enum-max",
        help="Cap on generated candidate names probed per run (default 300).",
    ),
    output: str = typer.Option(
        "wily-report.json", "-o", "--output",
        help=(
            "Path to write the report to (single-target mode). For a single "
            "domain this behaves exactly as before. Ignored when --output-dir is "
            "used or when scanning multiple domains."
        ),
    ),
    output_dir: str = typer.Option(
        None, "--output-dir",
        help=(
            "Directory for per-domain reports. REQUIRED when scanning more than "
            "one domain: each target is written to "
            "<output-dir>/<domain>.json (plus .html/.sarif when --format asks). "
            "The directory is created if missing."
        ),
    ),
    report_format: list[str] = typer.Option(
        None, "-f", "--format",
        help=(
            "Report format(s): json, html, sarif. Repeatable and/or "
            "comma-separated (e.g. --format html,sarif). Default: json. "
            "Non-JSON formats are written as siblings of -o with their own "
            "extension (wily-report.html, wily-report.sarif)."
        ),
    ),
    show_leak: bool = typer.Option(
        False, "--show-leak",
        help=(
            "Write evidence UNREDACTED (captured AWS keys/tokens stay visible "
            "in the report). For a controlled demo only - off by default, which "
            "redacts secrets."
        ),
    ),
    burp_xml: str = typer.Option(
        None, "--burp-xml",
        help=(
            "Import a Burp Suite 'Save items' XML export instead of (or alongside) "
            "live discovery. Endpoints/tokens/S3 links are parsed offline and the "
            "in-scope endpoints are fed into the scan queue."
        ),
    ),
    import_har: str = typer.Option(
        None, "--import-har",
        help=(
            "Import a HAR capture (browser/DevTools). Same offline parse as "
            "--burp-xml: endpoints, bearer tokens and S3 links are extracted."
        ),
    ),
    scope_bucket: list[str] = typer.Option(
        None, "--scope-bucket",
        help="S3 bucket name or glob pattern in scope (e.g. 'target-*'). Repeatable.",
    ),
    scope_account: list[str] = typer.Option(
        None, "--scope-account",
        help=(
            "AWS account id or ARN prefix in scope (e.g. 123456789012 or "
            "'arn:aws:iam::123456789012:*'). Restricts IAM analysis. Repeatable."
        ),
    ),
    scope_config: str = typer.Option(
        None, "--scope-config",
        help="JSON/YAML file with 'buckets', 'accounts' and 'exclude' scope lists.",
    ),
    jwt_secret_wordlist: str = typer.Option(
        None, "--jwt-secret-wordlist",
        help=(
            "Path to an extra wordlist (one candidate per line) for the weak "
            "HS256 signing-secret check, appended to the built-in list. The "
            "check is local, read-only and hard-capped on attempts/time; a "
            "recovered secret is reported REDACTED (length + fingerprint only)."
        ),
    ),
    oob_server: str = typer.Option(
        None, "--oob-server",
        help=(
            "Opt-in: URL of a YOUR-OWN interactsh-compatible OOB interaction "
            "server to confirm blind SSRF / jku / x5u against REMOTE targets "
            "(no inbound listener needed). No default server ships; you supply "
            "the endpoint. Falls back cleanly if unreachable."
        ),
    ),
    oob_bind: str = typer.Option(
        None, "--oob-bind",
        help=(
            "Opt-in: bind the self-hosted OOB canary to a reachable interface "
            "(HOST, HOST:PORT or :PORT, default 0.0.0.0:<random>) instead of "
            "loopback, so a remote target can reach it. Pair with "
            "--oob-public-url to advertise the externally reachable address."
        ),
    ),
    oob_public_url: str = typer.Option(
        None, "--oob-public-url",
        help=(
            "Opt-in: the externally reachable base URL (e.g. http://PUBLIC_IP:8000) "
            "the self-hosted canary advertises in forged URLs, when bound to a "
            "non-loopback interface for remote-target OOB confirmation."
        ),
    ),
    feedback_store: str = typer.Option(
        None, "--feedback-store",
        help=(
            "Path to a local JSONL feedback log (see `wily triage`). If given, "
            "findings whose hash matches a prior --valid/--fp decision are "
            "annotated with evidence['feedback_verdict'] - informational only, "
            "never drops or reorders a finding."
        ),
    ),
    ml_model: str = typer.Option(
        None, "--ml-model",
        help=(
            "Opt-in: path to a trained triage model (joblib, built by "
            "ml/build_dataset.py + ml/train.py). When given, findings are "
            "re-ranked and annotated with evidence['ml_valid_probability']; the "
            "model only reorders/annotates and never drops a finding. Requires "
            "the [ml] extra. Without this flag, ranking is heuristic-only and "
            "unchanged."
        ),
    ),
    fail_on: FailOn = typer.Option(
        FailOn.none, "--fail-on",
        case_sensitive=False,
        help=(
            "CI gate: exit non-zero if any finding is at or above this severity, "
            "so a pipeline can stop on it. Checked AFTER the triage layer, and a "
            "finding marked a false positive in --feedback-store never counts. "
            "Exit codes: 0 = clean (or 'none'); 1 = gate failed (findings at or "
            "above --fail-on); 2 = usage error or scan failure. A crash never "
            "looks like a gate hit. Default 'none' (never fails the build)."
        ),
    ),
) -> None:
    """The full bundle, automatically (Discovery + Auth Bypass + CORS + SSRF)
    against one or more domains, enabling JWT/BOLA/IAM based on the inputs you
    provide. With several domains, each gets its own separate report."""
    try:
        targets = scan_all.collect_targets(domains or [], targets_file)
    except OSError as e:
        typer.echo(f"Could not read --targets-file: {e}", err=True)
        raise typer.Exit(code=2) from e

    if not targets and not iam_file and not burp_xml and not import_har:
        typer.echo(
            "You must provide at least one domain, --targets-file, --iam-file, "
            "--burp-xml or --import-har at minimum. Try: wily scan --help",
            err=True,
        )
        raise typer.Exit(code=2)

    if len(targets) > 1 and not output_dir:
        typer.echo(
            f"{len(targets)} targets given but no --output-dir. A single -o would "
            "overwrite one report per domain; pass --output-dir DIR to write one "
            "<domain>.json per target.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        results = asyncio.run(
            scan_all.run_scans(
                targets=targets,
                output=output,
                output_dir=output_dir,
                token=token,
                identities_raw=identity or [],
                iam_file=iam_file,
                allow_local=allow_local,
                blind=blind,
                auto_token=auto_token,
                auto_canary=auto_canary,
                report_formats=report_format or [],
                confirm_destructive=confirm_destructive,
                confirm_owned_infra=confirm_owned_infra,
                confirm_s3_writes=confirm_s3_writes,
                probe_live=probe_live,
                cloud_enum=cloud_enum,
                cloud_keywords=cloud_keyword or [],
                cloud_enum_wordlist=cloud_enum_wordlist,
                cloud_enum_max=cloud_enum_max,
                show_leak=show_leak,
                burp_xml=burp_xml,
                import_har=import_har,
                scope_buckets=scope_bucket or [],
                scope_accounts=scope_account or [],
                scope_config=scope_config,
                feedback_store=feedback_store,
                use_rules=use_rules,
                jwt_secret_wordlist=jwt_secret_wordlist,
                oob_server=oob_server,
                oob_bind=oob_bind,
                oob_public_url=oob_public_url,
                ml_model=ml_model,
            )
        )
    except Exception as e:
        # Any failure in the scan itself is an operational error, not a gate
        # hit. Exit 2 (never 1) so a pipeline can tell "the tool broke" apart
        # from "the gate found something".
        typer.echo(f"Scan failed: {e}", err=True)
        raise typer.Exit(code=2) from e

    # CI gate: fail the build if findings crossed the chosen severity. A no-op
    # when --fail-on is 'none' (the default), so existing behaviour is unchanged.
    gate = evaluate_gate(results or {}, fail_on)
    for line in format_gate_lines(gate):
        typer.echo(line)
    if gate.failed:
        raise typer.Exit(code=gate.exit_code)


app.command("jwt", help="JWT Tampering checks only (a single, focused module).")(jwt_cmd.run)
app.command("authz", help="API Auth Bypass checks only.")(authz_cmd.run)
app.command("iam", help="IAM Privilege Escalation analysis only.")(iam_cmd.run)
app.command("ssrf", help="IMDS Cloud SSRF checks only.")(ssrf_cmd.run)
app.command("discover", help="Discover real endpoints (OpenAPI/JS/wordlist) only, with no scanning.")(discover_cmd.run)
app.command("triage", help="Record --valid/--fp analyst decisions against a prior scan report (feedback loop).")(triage_cmd.run)
app.add_typer(templates_cmd.app, name="templates")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"wily {__version__}")
        raise typer.Exit()


_MAIN_EPILOG = """
[bold]Examples[/bold]

  [dim]# Full scan of one target, all three report formats[/dim]
  wily scan https://api.example.com -o report --format json,html,sarif

  [dim]# Several targets - a separate report for each[/dim]
  wily scan a.example.com b.example.com --output-dir reports/

  [dim]# JWT checks with a token, and fail a CI build on High+ findings[/dim]
  wily scan https://api.example.com --token "$JWT" --fail-on high

  [dim]# Run a single focused module[/dim]
  wily jwt https://api.example.com --token "$JWT"
  wily iam --iam-file account-auth-details.json

[bold]Per-command help[/bold]

  Every command has its own detailed options. See them with:
  wily COMMAND -h     [dim](e.g. wily scan -h, wily jwt -h, wily ssrf -h)[/dim]
"""


@app.callback(invoke_without_command=True, epilog=_MAIN_EPILOG)
def main_callback(
    ctx: typer.Context,
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Don't print the banner."),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."
    ),
) -> None:
    # Print the banner on every invocation (like nuclei), unless --quiet.
    print_banner(quiet=quiet)
    # Bare ``wily`` with no sub-command: show only the banner (plus a short
    # hint), and exit cleanly. The full command/option listing is reserved for
    # ``wily -h`` / ``wily --help``.
    if ctx.invoked_subcommand is None:
        if not quiet:
            typer.echo("Run 'wily -h' to see the available commands.", err=True)
        raise typer.Exit()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
