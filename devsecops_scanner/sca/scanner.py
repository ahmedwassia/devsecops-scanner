"""Dependency manifest parsing and checks against the bundled advisory database."""

import json
import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from devsecops_scanner.models import Finding, Severity


ADVISORY_FILE = Path(__file__).with_name("advisories.json")


def load_advisories(path: Path = ADVISORY_FILE) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, list):
        raise ValueError("Advisory database must contain a JSON array.")
    return data


def _poetry_requirement(name: str, constraint: str) -> str:
    """Convert Poetry caret/tilde constraints to a PEP 508 version range."""
    match = re.fullmatch(r"\s*(\^|~)\s*([0-9][A-Za-z0-9.+!-]*)\s*", constraint)
    if match is None:
        return f"{name}{constraint}"
    operator, raw_version = match.groups()
    try:
        version = Version(raw_version)
    except InvalidVersion:
        return f"{name}{constraint}"
    release = list(version.release)
    release.extend([0] * (3 - len(release)))
    if operator == "~":
        release[1] += 1
        release[2] = 0
    else:
        bump = next((index for index, number in enumerate(release[:3]) if number), 2)
        release[bump] += 1
        for index in range(bump + 1, 3):
            release[index] = 0
    upper_bound = ".".join(str(part) for part in release[:3])
    return f"{name}>={version},<{upper_bound}"


def _pyproject_requirements(path: Path) -> list[str]:
    with path.open("rb") as file:
        data = tomllib.load(file)
    project = data.get("project", {})
    raw_requirements = project.get("dependencies", []) if isinstance(project, dict) else []
    for group in (project.get("optional-dependencies", {}) if isinstance(project, dict) else {}).values():
        raw_requirements.extend(group)

    requirements = [str(item) for item in raw_requirements]
    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict):
        dependencies = poetry.get("dependencies", {})
        if isinstance(dependencies, dict):
            for name, constraint in dependencies.items():
                if name.lower() == "python":
                    continue
                if isinstance(constraint, str):
                    requirements.append(_poetry_requirement(name, constraint))
                elif isinstance(constraint, dict) and isinstance(constraint.get("version"), str):
                    requirements.append(_poetry_requirement(name, constraint["version"]))
    return requirements


def _parse_requirement(text: str) -> tuple[str, str, str] | None:
    item = text.strip()
    if not item or item.startswith("#") or item.startswith(("-e ", "--")):
        return None
    item = re.split(r"\s+#", item, maxsplit=1)[0].strip()
    try:
        requirement = Requirement(item)
    except InvalidRequirement:
        return None
    if requirement.url or not requirement.specifier:
        return canonicalize_name(requirement.name), "", requirement.name
    return canonicalize_name(requirement.name), str(requirement.specifier), requirement.name


def _manifest_requirements(path: Path) -> list[tuple[str, str, str]]:
    if path.name == "requirements.txt":
        raw = path.read_text(encoding="utf-8").splitlines()
    elif path.name == "pyproject.toml":
        raw = _pyproject_requirements(path)
    else:
        return []
    parsed = [_parse_requirement(text) for text in raw]
    return [item for item in parsed if item is not None]


def scan_manifests(manifests: list[tuple[Path, str]],
                   advisory_path: Path = ADVISORY_FILE) -> list[Finding]:
    """Scan supported manifests. Input paths are paired with report-relative paths."""
    advisories = load_advisories(advisory_path)
    findings: list[Finding] = []
    for manifest, relative_path in manifests:
        for package, declared_specifier, display_name in _manifest_requirements(manifest):
            specifier = Requirement(f"{package}{declared_specifier}").specifier
            for advisory in advisories:
                if canonicalize_name(str(advisory["package"])) != package:
                    continue
                affected = next(
                    (str(version) for version in advisory["affected_versions"]
                     if Version(str(version)) in specifier),
                    None,
                )
                if affected is None:
                    continue
                findings.append(Finding(
                    rule_id=f"SCA-{advisory['cve']}", title=str(advisory["title"]),
                    severity=Severity.parse(str(advisory["severity"])),
                    file_path=relative_path, line=1,
                    message=(f"The declared version constraint for {display_name} allows "
                             f"affected version {affected}, listed in the bundled advisory database."),
                    category="SCA",
                    recommendation=(
                        f"Upgrade {display_name} to {advisory['fixed_version']} or later."
                    ),
                    cve=str(advisory["cve"]),
                ))
    return findings
