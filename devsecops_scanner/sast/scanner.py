"""Python-focused static checks for common security mistakes."""

import ast
import logging
import re

from devsecops_scanner.models import Finding, Severity


logger = logging.getLogger(__name__)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    return ""


def _has_interpolation(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format"
    return False


def scan_file(relative_path: str, source: str) -> list[Finding]:
    """Return SAST findings for a Python source file."""
    try:
        tree = ast.parse(source, filename=relative_path)
    except SyntaxError as exc:
        logger.warning("Unable to parse Python file %s at line %s.", relative_path, exc.lineno)
        return []

    findings: list[Finding] = []

    def add(rule: str, title: str, severity: Severity, node: ast.AST, message: str,
            recommendation: str) -> None:
        findings.append(Finding(
            rule_id=rule, title=title, severity=severity, file_path=relative_path,
            line=getattr(node, "lineno", 1), message=message, category="SAST",
            recommendation=recommendation,
        ))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            names = [
                target.id.lower() for target in targets if isinstance(target, ast.Name)
            ]
            if any(re.search(r"(password|passwd|secret|api_key|access_token|private_key)", name)
                   for name in names) and isinstance(value, ast.Constant) and isinstance(value.value, str):
                if len(value.value) >= 4 and value.value.lower() not in {
                    "changeme", "change_me", "your_password", "your_api_key", "example",
                }:
                    add("SAST-001", "Possible hardcoded credential", Severity.HIGH, node,
                        "A credential-like variable is assigned a string literal.",
                        "Load credentials from a secret manager or environment variable.")

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"eval", "exec"}:
            add("SAST-002", "Dynamic code execution", Severity.HIGH, node,
                f"{name}() executes dynamically constructed code.",
                "Avoid dynamic evaluation; use a safe parser or explicit dispatch.")
        if name in {"os.system", "os.popen"}:
            add("SAST-003", "Shell command execution", Severity.HIGH, node,
                f"{name}() invokes a shell with a command string.",
                "Use subprocess.run with an argument list and validate untrusted inputs.")
        if name in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                    "subprocess.check_output", "subprocess.check_call"}:
            shell_true = any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True for keyword in node.keywords
            )
            if shell_true:
                add("SAST-003", "Shell command execution", Severity.HIGH, node,
                    "subprocess is called with shell=True.",
                    "Pass an argument list with shell=False and validate untrusted inputs.")
        if name.endswith(".execute") and node.args and _has_interpolation(node.args[0]):
            add("SAST-004", "Possible SQL injection", Severity.HIGH, node,
                "SQL passed to execute() appears to use string interpolation or concatenation.",
                "Use parameterized queries instead of assembling SQL strings.")
        if name in {
            "requests.get", "requests.post", "requests.put", "requests.patch",
            "requests.delete", "requests.request", "httpx.get", "httpx.post",
            "httpx.put", "httpx.patch", "httpx.delete", "httpx.request",
        }:
            if any(keyword.arg == "verify" and isinstance(keyword.value, ast.Constant)
                   and keyword.value.value is False for keyword in node.keywords):
                add("SAST-005", "TLS certificate verification disabled", Severity.HIGH, node,
                    "The HTTP client disables TLS certificate verification.",
                    "Enable certificate verification and configure trusted certificates.")
        if name in {"ssl._create_unverified_context"}:
            add("SAST-005", "TLS certificate verification disabled", Severity.HIGH, node,
                "An unverified TLS context is created.",
                "Use ssl.create_default_context() with certificate verification enabled.")
        if name in {"urllib3.PoolManager", "urllib3.HTTPSConnectionPool"} and any(
            keyword.arg == "cert_reqs"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value in {"CERT_NONE", 0}
            for keyword in node.keywords
        ):
            add("SAST-005", "TLS certificate verification disabled", Severity.HIGH, node,
                "urllib3 is configured without certificate verification.",
                "Require valid certificates with CERT_REQUIRED.")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for target in targets:
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
                add("SAST-005", "TLS hostname verification disabled", Severity.HIGH, node,
                    "TLS hostname verification is disabled.",
                    "Keep hostname verification enabled for TLS connections.")
            if target.attr == "verify" and isinstance(value, ast.Constant) and value.value is False:
                add("SAST-005", "TLS certificate verification disabled", Severity.HIGH, node,
                    "The HTTP client disables TLS certificate verification.",
                    "Enable certificate verification and configure trusted certificates.")
            if target.attr == "verify_mode" and (
                (isinstance(value, ast.Constant) and value.value == 0)
                or (isinstance(value, ast.Attribute) and value.attr == "CERT_NONE")
            ):
                add("SAST-005", "TLS certificate verification disabled", Severity.HIGH, node,
                    "TLS certificate verification is disabled.",
                    "Use ssl.CERT_REQUIRED and a trusted certificate store.")
    return findings
