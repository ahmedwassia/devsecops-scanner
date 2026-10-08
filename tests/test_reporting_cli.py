import json
from pathlib import Path

from click.testing import CliRunner

from devsecops_scanner.cli import main
from devsecops_scanner.models import Finding, Severity
from devsecops_scanner.reporter.report import render_html, render_json, render_markdown


def test_report_formats_include_summary_and_findings():
    finding = Finding(
        rule_id="SAST-002", title="<unsafe>", severity=Severity.HIGH,
        file_path="app.py", line=7, message="Unsafe code", category="SAST",
        recommendation="Use a safe alternative.",
    )
    json_report = json.loads(render_json([finding], "."))
    assert json_report["summary"]["by_severity"]["High"] == 1
    assert json_report["findings"][0]["severity"] == "High"
    assert "SAST-002" in render_markdown([finding], ".")
    html = render_html([finding], ".")
    assert "&lt;unsafe&gt;" in html
    assert "Filter findings" in html


def test_cli_writes_report_and_enforces_fail_on(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text("eval(input())\n", encoding="utf-8")
    output = tmp_path / "nested" / "report.json"

    result = CliRunner().invoke(
        main, ["scan", "--path", str(tmp_path), "--output", str(output), "--fail-on", "high"],
    )

    assert result.exit_code == 1
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["total"] >= 1


def test_cli_rejects_unsupported_report_extension(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", "--path", str(tmp_path), "--output", str(tmp_path / "report.csv")],
    )
    assert result.exit_code != 0
    assert "Output extension" in result.output
