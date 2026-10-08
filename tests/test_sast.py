from pathlib import Path

from devsecops_scanner.models import Severity
from devsecops_scanner.sast.scanner import scan_file


FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable.py"


def test_sast_detects_required_python_issue_categories():
    source = FIXTURE.read_text(encoding="utf-8")
    findings = scan_file("vulnerable.py", source)
    rule_ids = {item.rule_id for item in findings}

    assert {"SAST-001", "SAST-002", "SAST-003", "SAST-004", "SAST-005"} <= rule_ids
    assert all(item.severity == Severity.HIGH for item in findings)


def test_sast_does_not_flag_parameterized_query_or_safe_subprocess():
    source = """
import subprocess
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
subprocess.run(["echo", user_input], check=True)
"""
    assert scan_file("safe.py", source) == []
    tls_findings = scan_file("tls.py", "session.verify = False\n")
    assert {item.rule_id for item in tls_findings} == {"SAST-005"}
