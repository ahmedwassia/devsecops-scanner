from pathlib import Path

from devsecops_scanner.models import Severity
from devsecops_scanner.secrets.scanner import scan_file, shannon_entropy


def test_entropy_and_known_token_detection_redact_values():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("aB3dE5fG7hJ9kL2mN4pQ") > 3.5

    source = (
        'aws = "AKIA1234567890ABCDEF"\n'
        'github_token = "ghp_0123456789abcdefghijABCDEFGHIJ12"\n'
        'slack_token = "xoxb-12345678901234567890-abcdef"\n'
        'api_key = "aB3dE5fG7hJ9kL2mN4pQ"\n'
        'aws_secret_access_key = "sE7fG9hJ2kL4mN6pQ8rT0vX1zA3cD5eF"\n'
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )
    findings = scan_file(Path("secrets.txt"), "secrets.txt", source)

    assert {item.rule_id for item in findings} == {
        "SECRET-AWS", "SECRET-GITHUB", "SECRET-SLACK",
        "SECRET-GENERIC", "SECRET-PRIVATE-KEY",
    }
    assert next(item for item in findings if item.rule_id == "SECRET-GENERIC").severity == Severity.HIGH
    assert next(item for item in findings if item.rule_id == "SECRET-AWS").severity == Severity.CRITICAL
    assert all("AKIA" not in item.message and "aB3d" not in item.message for item in findings)


def test_generic_low_entropy_value_is_ignored():
    assert scan_file(Path("safe.env"), "safe.env", 'api_key="aaaaaaaaaaaaaaaaaaaa"\n') == []
