"""Multi-domain scanning for ``wily scan``:

  - target collection: positional domains + a --targets-file are combined,
    blank/comment lines are ignored, and duplicates are removed (order kept).
  - domain -> filename sanitization.
  - the run_scans orchestrator writes ONE separate report per domain and keeps
    single-domain behavior byte-for-byte backward compatible.
  - CLI wiring: multiple positional targets, --targets-file, and the
    "multiple targets need --output-dir" guard.
"""

import asyncio
import json

import pytest
from typer.testing import CliRunner

from wily.cli.app import app
from wily.cli.commands import scan_all

runner = CliRunner()


# --------------------------------------------------------------- target parsing


def test_read_targets_file_ignores_blanks_and_comments(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text(
        "\n".join(  # noqa: FLY002 - keep the fixture readable as one line per target
            [
                "# this is a comment",
                "a.com",
                "   ",
                "  b.com  ",
                "",
                "#c.com commented out",
                "d.com",
            ]
        ),
        encoding="utf-8",
    )
    assert scan_all.read_targets_file(f) == ["a.com", "b.com", "d.com"]


def test_collect_targets_combines_and_dedups(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("b.com\nc.com\na.com\n", encoding="utf-8")
    # positional args come first; file entries after; a.com appears in both and
    # is kept only once, at its first (positional) position.
    assert scan_all.collect_targets(["a.com", "x.com"], f) == [
        "a.com",
        "x.com",
        "b.com",
        "c.com",
    ]


def test_collect_targets_positional_only():
    assert scan_all.collect_targets(["a.com", "a.com", "b.com"], None) == [
        "a.com",
        "b.com",
    ]


def test_collect_targets_file_only(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("a.com\nb.com\n", encoding="utf-8")
    assert scan_all.collect_targets([], f) == ["a.com", "b.com"]


def test_collect_targets_empty():
    assert scan_all.collect_targets([], None) == []


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("example.com", "example.com"),
        ("https://example.com/path", "example.com"),
        ("http://a.b.c", "a.b.c"),
        ("EXAMPLE.com", "example.com"),
        ("weird/\\:*name", "weird____name"),
    ],
)
def test_sanitize_domain_filename(domain, expected):
    assert scan_all.sanitize_domain_filename(domain) == expected


# ------------------------------------------------------- orchestrator behavior


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace run_full_scan with a fake that records its calls and writes a
    tiny JSON report at the output path (so file-per-domain can be asserted
    without any network/discovery)."""
    calls = []

    async def _fake_run_full_scan(*, domain, output, **kwargs):
        calls.append({"domain": domain, "output": output, "kwargs": kwargs})
        from pathlib import Path

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(
            json.dumps({"domain": domain, "findings": []}), encoding="utf-8"
        )

    monkeypatch.setattr(scan_all, "run_full_scan", _fake_run_full_scan)
    return calls


def test_single_target_no_output_dir_is_legacy(fake_scan, tmp_path):
    out = tmp_path / "report.json"
    asyncio.run(
        scan_all.run_scans(targets=["example.com"], output=str(out), output_dir=None)
    )
    # Exactly one run, writing to the -o path verbatim (backward compatible).
    assert len(fake_scan) == 1
    assert fake_scan[0]["domain"] == "example.com"
    assert fake_scan[0]["output"] == str(out)
    assert out.exists()


def test_no_targets_runs_once_with_none_domain(fake_scan, tmp_path):
    out = tmp_path / "report.json"
    asyncio.run(scan_all.run_scans(targets=[], output=str(out), output_dir=None))
    assert len(fake_scan) == 1
    assert fake_scan[0]["domain"] is None
    assert fake_scan[0]["output"] == str(out)


def test_multiple_targets_write_separate_reports(fake_scan, tmp_path):
    out_dir = tmp_path / "reports"
    asyncio.run(
        scan_all.run_scans(
            targets=["a.com", "b.com", "c.com"],
            output="wily-report.json",
            output_dir=str(out_dir),
        )
    )
    assert len(fake_scan) == 3
    assert [c["domain"] for c in fake_scan] == ["a.com", "b.com", "c.com"]
    # One separate report file per domain, named after the sanitized domain.
    for name in ("a.com", "b.com", "c.com"):
        report = out_dir / name / "report.json"
        assert report.exists(), f"missing report for {name}"
        assert json.loads(report.read_text(encoding="utf-8"))["domain"] == name
    # The reports are genuinely distinct files (no single merged report).
    outputs = {c["output"] for c in fake_scan}
    assert len(outputs) == 3


def test_output_dir_created_if_missing(fake_scan, tmp_path):
    out_dir = tmp_path / "nested" / "reports"
    assert not out_dir.exists()
    asyncio.run(
        scan_all.run_scans(
            targets=["a.com", "b.com"],
            output="wily-report.json",
            output_dir=str(out_dir),
        )
    )
    assert out_dir.is_dir()
    assert (out_dir / "a.com" / "report.json").exists()


def test_colliding_sanitized_names_get_unique_files(fake_scan, tmp_path):
    out_dir = tmp_path / "reports"
    # Two distinct inputs that sanitize to the same stem ("a.com").
    asyncio.run(
        scan_all.run_scans(
            targets=["a.com", "https://a.com/"],
            output="wily-report.json",
            output_dir=str(out_dir),
        )
    )
    assert len(fake_scan) == 2
    outputs = {c["output"] for c in fake_scan}
    assert len(outputs) == 2  # no overwrite
    assert (out_dir / "a.com" / "report.json").exists()
    assert (out_dir / "a.com-2" / "report.json").exists()


def test_single_target_with_output_dir_uses_dir(fake_scan, tmp_path):
    out_dir = tmp_path / "reports"
    asyncio.run(
        scan_all.run_scans(
            targets=["example.com"],
            output="wily-report.json",
            output_dir=str(out_dir),
        )
    )
    assert len(fake_scan) == 1
    assert fake_scan[0]["output"] == str(out_dir / "example.com" / "report.json")


def test_scan_kwargs_forwarded_per_domain(fake_scan, tmp_path):
    out_dir = tmp_path / "reports"
    asyncio.run(
        scan_all.run_scans(
            targets=["a.com", "b.com"],
            output="wily-report.json",
            output_dir=str(out_dir),
            token="jwt-value",
            report_formats=["html", "sarif"],
        )
    )
    for call in fake_scan:
        assert call["kwargs"]["token"] == "jwt-value"
        assert call["kwargs"]["report_formats"] == ["html", "sarif"]


# --------------------------------------------------------------------- CLI wiring


@pytest.fixture
def captured_run_scans(monkeypatch):
    """Capture the arguments the CLI passes to run_scans (no scan runs)."""
    captured = {}

    async def _fake_run_scans(*, targets, output, output_dir, **kwargs):
        captured["targets"] = targets
        captured["output"] = output
        captured["output_dir"] = output_dir
        captured["kwargs"] = kwargs

    monkeypatch.setattr(scan_all, "run_scans", _fake_run_scans)
    return captured


def test_cli_single_domain_backward_compatible(captured_run_scans):
    result = runner.invoke(app, ["scan", "example.com", "-o", "r.json"])
    assert result.exit_code == 0
    assert captured_run_scans["targets"] == ["example.com"]
    assert captured_run_scans["output"] == "r.json"
    assert captured_run_scans["output_dir"] is None


def test_cli_multiple_positional_targets(captured_run_scans):
    result = runner.invoke(
        app, ["scan", "a.com", "b.com", "c.com", "--output-dir", "reports"]
    )
    assert result.exit_code == 0
    assert captured_run_scans["targets"] == ["a.com", "b.com", "c.com"]
    assert captured_run_scans["output_dir"] == "reports"


def test_cli_targets_file_merged_with_positional(captured_run_scans, tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# header\nb.com\n\na.com\nd.com\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", "a.com", "--targets-file", str(f), "--output-dir", "out"],
    )
    assert result.exit_code == 0
    # a.com from positional (first), then file's b.com and d.com; a.com deduped.
    assert captured_run_scans["targets"] == ["a.com", "b.com", "d.com"]


def test_cli_multiple_targets_without_output_dir_errors(captured_run_scans):
    result = runner.invoke(app, ["scan", "a.com", "b.com"])
    # Usage error, not a gate hit: exit 2 so it is distinct from exit 1.
    assert result.exit_code == 2
    assert "--output-dir" in result.output
    # The scan must not have started.
    assert captured_run_scans == {}


def test_cli_no_target_and_no_input_errors(captured_run_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert captured_run_scans == {}


def test_cli_missing_targets_file_errors(captured_run_scans, tmp_path):
    missing = tmp_path / "nope.txt"
    result = runner.invoke(app, ["scan", "--targets-file", str(missing)])
    assert result.exit_code == 2
    assert "targets-file" in result.output
    assert captured_run_scans == {}
