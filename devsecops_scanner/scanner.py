"""Repository traversal and orchestration for all scanner engines."""

import fnmatch
import logging
from pathlib import Path

from devsecops_scanner.models import Finding
from devsecops_scanner.sast.scanner import scan_file as scan_python
from devsecops_scanner.sca.scanner import scan_manifests
from devsecops_scanner.secrets.scanner import scan_file as scan_secrets


DEFAULT_IGNORES = (
    ".git/**", ".venv/**", "venv/**", "env/**", "__pycache__/**",
    "node_modules/**", ".tox/**", "dist/**", "build/**",
)
TEXT_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".php", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env",
    ".txt", ".sh", ".dockerfile", ".xml", ".md", ".rst", ".pem", ".key",
    ".properties", ".conf", ".csv",
}
TEXT_FILENAMES = {"Dockerfile", "Makefile", ".npmrc", ".pypirc", ".netrc"}
MAX_FILE_SIZE = 1_000_000
logger = logging.getLogger(__name__)


def _is_excluded(relative_path: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(relative_path, pattern)
        or (pattern.endswith("/**") and relative_path.startswith(pattern[:-3] + "/"))
        for pattern in patterns
    )


def scan_path(path: Path, excludes: tuple[str, ...] = ()) -> list[Finding]:
    """Scan files and manifests below a file or directory path."""
    root = path.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root}")
    if not root.is_dir() and not root.is_file():
        raise ValueError(f"Scan path is not a regular file or directory: {root}")
    base = root if root.is_dir() else root.parent
    patterns = DEFAULT_IGNORES + excludes
    files = [root] if root.is_file() else sorted(
        item for item in root.rglob("*")
        if item.is_file() and not item.is_symlink()
        and not _is_excluded(item.relative_to(base).as_posix(), patterns)
    )
    findings: list[Finding] = []
    manifests: list[tuple[Path, str]] = []
    for file_path in files:
        relative_path = file_path.relative_to(base).as_posix()
        if file_path.name in {"requirements.txt", "pyproject.toml"}:
            manifests.append((file_path, relative_path))
        if (file_path.suffix.lower() not in TEXT_SUFFIXES
                and file_path.name not in TEXT_FILENAMES
                and not file_path.name.startswith(".env")):
            continue
        if file_path.stat().st_size > MAX_FILE_SIZE:
            logger.warning(
                "Skipping %s because it exceeds the %s-byte scan limit.",
                relative_path, MAX_FILE_SIZE,
            )
            continue
        source = file_path.read_text(encoding="utf-8", errors="replace")
        findings.extend(scan_secrets(file_path, relative_path, source))
        if file_path.suffix.lower() in {".py", ".pyi"}:
            findings.extend(scan_python(relative_path, source))
    findings.extend(scan_manifests(manifests))
    return sorted(findings, key=lambda finding: (
        -int(finding.severity), finding.file_path, finding.line, finding.rule_id,
    ))
