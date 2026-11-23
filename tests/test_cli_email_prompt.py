"""The interactive "email me the report" prompt in `wily scan`.

Key behaviors:
  - In a real interactive terminal, the prompt appears for ANY scan (a single
    domain included) - a scan can take a while regardless of target count.
  - Pressing Enter (an empty answer) skips it and the scan proceeds exactly
    as before - no --email, no behavior change.
  - --email always wins and skips the prompt (so scripts/CI never block on
    stdin waiting for an answer).
  - A non-interactive stdin (piped, redirected, CI) never prompts at all.
"""

from unittest.mock import patch

from typer.testing import CliRunner

from wily.cli.app import app

runner = CliRunner()


def _patched_run_scans(monkeypatch):
    """Replace run_scans with a fake that records whatever recipient-sending
    the CLI attempted, without doing any real scan or network I/O."""
    calls = {}

    async def _fake_run_scans(*, targets, output, output_dir, **kwargs):
        calls["targets"] = targets
        return {t: [] for t in targets}

    monkeypatch.setattr("wily.cli.commands.scan_all.run_scans", _fake_run_scans)
    return calls


def test_prompt_shown_for_single_domain_when_interactive(monkeypatch):
    """A single-domain scan still asks - it is not limited to multi-target."""
    _patched_run_scans(monkeypatch)
    monkeypatch.setattr("wily.cli.app._stdin_is_interactive", lambda: True)

    with patch("wily.cli.app.typer.prompt", return_value="") as mock_prompt:
        result = runner.invoke(app, ["scan", "example.com", "-o", "r.json"])

    assert result.exit_code == 0
    assert mock_prompt.called, "the email prompt must appear even for one domain"


def test_empty_answer_skips_email_and_scan_proceeds_normally(monkeypatch):
    """Pressing Enter (empty string) must not email anything and must not
    change the scan's own exit code."""
    _patched_run_scans(monkeypatch)
    monkeypatch.setattr("wily.cli.app._stdin_is_interactive", lambda: True)

    sent = []
    monkeypatch.setattr(
        "wily.cli.app.send_report_via_http",
        lambda **kwargs: sent.append(kwargs) or {"attachment": "x"},
    )

    with patch("wily.cli.app.typer.prompt", return_value=""):
        result = runner.invoke(app, ["scan", "example.com", "-o", "r.json"])

    assert result.exit_code == 0
    assert sent == [], "no email should be sent when the user presses Enter"


def test_email_answer_is_used_to_send_the_report(monkeypatch):
    _patched_run_scans(monkeypatch)
    monkeypatch.setattr("wily.cli.app._stdin_is_interactive", lambda: True)

    sent = []
    monkeypatch.setattr(
        "wily.cli.app.send_report_via_http",
        lambda **kwargs: sent.append(kwargs) or {"attachment": "r.json"},
    )

    with patch("wily.cli.app.typer.prompt", return_value="user@example.com"):
        result = runner.invoke(app, ["scan", "example.com", "-o", "r.json"])

    assert result.exit_code == 0
    assert len(sent) == 1
    assert sent[0]["recipient"] == "user@example.com"


def test_explicit_email_flag_skips_the_prompt(monkeypatch):
    """--email wins outright: no prompt, even though stdin is "interactive"."""
    _patched_run_scans(monkeypatch)
    monkeypatch.setattr("wily.cli.app._stdin_is_interactive", lambda: True)

    sent = []
    monkeypatch.setattr(
        "wily.cli.app.send_report_via_http",
        lambda **kwargs: sent.append(kwargs) or {"attachment": "r.json"},
    )

    with patch("wily.cli.app.typer.prompt") as mock_prompt:
        result = runner.invoke(
            app, ["scan", "example.com", "-o", "r.json", "--email", "ci@example.com"]
        )

    assert result.exit_code == 0
    assert not mock_prompt.called
    assert sent[0]["recipient"] == "ci@example.com"


def test_non_interactive_stdin_never_prompts(monkeypatch):
    """A script/CI run (piped stdin) must never block waiting for an answer."""
    _patched_run_scans(monkeypatch)
    monkeypatch.setattr("wily.cli.app._stdin_is_interactive", lambda: False)

    with patch("wily.cli.app.typer.prompt") as mock_prompt:
        result = runner.invoke(app, ["scan", "example.com", "-o", "r.json"])

    assert result.exit_code == 0
    assert not mock_prompt.called
