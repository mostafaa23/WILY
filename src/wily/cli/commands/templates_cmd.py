"""wily templates <validate|list>

Inspect the declarative YAML rule set under ``src/wily/templates/rules``
(or a directory passed with ``--rules-dir``). ``validate`` reports which
rules load cleanly and why any are rejected; ``list`` shows the loadable
rules and their key fields.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from wily.templates.loader import default_rules_dir, validate_rules

app = typer.Typer(
    name="templates",
    help="Inspect the declarative YAML rule set (validate / list).",
    no_args_is_help=True,
)

console = Console(stderr=True)


def _resolve_dir(rules_dir: str | None) -> Path:
    return Path(rules_dir) if rules_dir else default_rules_dir()


@app.command("validate")
def validate(
    rules_dir: str = typer.Option(
        None, "--rules-dir",
        help="Directory of YAML rules (default: Wily's built-in rules).",
    ),
) -> None:
    """Validate every YAML rule and report valid vs. invalid ones.

    Exit code 0 when every rule is valid, 1 when at least one is invalid, so
    a CI pipeline can gate on rule health.
    """
    root = _resolve_dir(rules_dir)
    if not root.exists():
        console.print(f"[red][x][/red] Rules directory not found: {root}")
        raise typer.Exit(code=2)

    result = validate_rules(root)
    valid, invalid = result["valid"], result["invalid"]

    console.print(
        f"[cyan][*][/cyan] Scanned [bold]{root}[/bold]: "
        f"{len(valid)} valid, {len(invalid)} invalid."
    )
    for template in valid:
        console.print(
            f"  [green][+][/green] {template.id} "
            f"([dim]{template.info.severity.value}/{template.info.category}[/dim])"
        )
    for path, reason in invalid:
        console.print(f"  [red][x][/red] {path.name}: {reason}")

    if invalid:
        raise typer.Exit(code=1)


@app.command("list")
def list_rules(
    rules_dir: str = typer.Option(
        None, "--rules-dir",
        help="Directory of YAML rules (default: Wily's built-in rules).",
    ),
) -> None:
    """List the rules that load cleanly, with their asset-type and matchers."""
    root = _resolve_dir(rules_dir)
    if not root.exists():
        console.print(f"[red][x][/red] Rules directory not found: {root}")
        raise typer.Exit(code=2)

    result = validate_rules(root)
    valid = result["valid"]

    if not valid:
        console.print(f"[yellow][-][/yellow] No valid rules found under {root}.")
        if result["invalid"]:
            console.print(
                f"[yellow][!][/yellow] {len(result['invalid'])} file(s) failed to "
                "load; run `wily templates validate` for details."
            )
        return

    table = Table(title=f"Rules ({len(valid)})")
    table.add_column("ID", style="cyan", overflow="fold")
    table.add_column("Severity")
    table.add_column("Category", style="red", overflow="fold")
    table.add_column("Asset type")
    table.add_column("Auth mode")
    table.add_column("Matchers", justify="right")
    for template in valid:
        table.add_row(
            template.id,
            template.info.severity.value,
            template.info.category,
            template.asset_type,
            template.authorization.mode.value,
            str(len(template.matchers)),
        )
    console.print(table)
