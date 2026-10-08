"""Pattern and entropy based detection of accidentally committed secrets."""

import math
import re
from collections import Counter
from pathlib import Path

from devsecops_scanner.models import Finding, Severity


PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("SECRET-AWS", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SECRET-GITHUB", "GitHub token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("SECRET-SLACK", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("SECRET-PRIVATE-KEY", "Private key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SECRET-GENERIC", "Possible hardcoded secret", re.compile(
        r"""(?i)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?(?:token|key)|"""
        r"""client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|"""
        r"""secret[_-]?(?:access[_-]?key|key)?|password|token)\b"""
        r"""\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{16,})""")),
)


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def scan_file(file_path: Path, relative_path: str, source: str,
              entropy_threshold: float = 3.5) -> list[Finding]:
    """Find known token shapes and high-entropy values assigned to secret-like names."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for line_number, line in enumerate(source.splitlines(), start=1):
        for rule, title, pattern in PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            secret = match.group(1) if rule == "SECRET-GENERIC" else match.group(0)
            if rule == "SECRET-GENERIC" and shannon_entropy(secret) < entropy_threshold:
                continue
            key = (rule, line_number)
            if rule == "SECRET-GENERIC" and any(
                (specific_rule, line_number) in seen
                for specific_rule, _, _ in PATTERNS[:-1]
            ):
                continue
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id=rule, title=title,
                severity=Severity.HIGH if rule == "SECRET-GENERIC" else Severity.CRITICAL,
                file_path=relative_path, line=line_number,
                message="A credential-like value was detected; the value is intentionally redacted.",
                category="Secrets",
                recommendation="Revoke and rotate the credential, then store it in a secret manager.",
            ))
    return findings
