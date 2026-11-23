"""Load every rule file under templates/rules/**/*.yaml and validate it
against templates.schema.Template before adding it to the run list.

Errors are collected rather than raised on the first bad file, so
``wily templates validate`` can report on every rule in one pass and a
single malformed file never hides the others.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from wily.templates.schema import Template


def default_rules_dir() -> Path:
    """The directory holding Wily's built-in YAML rules."""
    return Path(__file__).parent / "rules"


def _format_error(exc: Exception) -> str:
    """A compact one-line reason for a rule that failed to load."""
    if isinstance(exc, yaml.YAMLError):
        return f"invalid YAML: {str(exc).splitlines()[0]}"
    if isinstance(exc, ValidationError):
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        return f"schema validation failed: {problems}"
    return f"{type(exc).__name__}: {exc}"


def validate_rules(rules_dir: Path | str | None = None) -> dict:
    """Parse and validate every ``*.yaml`` rule under ``rules_dir``.

    Returns ``{"valid": [Template, ...], "invalid": [(path, reason), ...]}``.
    The walk is recursive and deterministic (sorted by path). A file that is
    unreadable, is not valid YAML, does not contain a mapping, or does not
    satisfy ``Template`` is reported in ``invalid`` instead of aborting.
    """
    root = Path(rules_dir) if rules_dir is not None else default_rules_dir()

    valid: list[Template] = []
    invalid: list[tuple[Path, str]] = []

    for path in sorted(root.rglob("*.yaml")):
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            invalid.append((path, _format_error(exc)))
            continue

        if not isinstance(data, dict):
            invalid.append(
                (path, "schema validation failed: file is empty or not a YAML mapping")
            )
            continue

        try:
            template = Template.model_validate(data)
        except ValidationError as exc:
            invalid.append((path, _format_error(exc)))
            continue

        valid.append(template)

    return {"valid": valid, "invalid": invalid}


def load_rules(rules_dir: Path | str | None = None) -> list[Template]:
    """Return only the valid ``Template`` objects under ``rules_dir``.

    Invalid files are skipped silently here; use :func:`validate_rules` when
    the caller needs to see *why* a rule was rejected.
    """
    return validate_rules(rules_dir)["valid"]
