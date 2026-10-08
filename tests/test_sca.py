import json
from pathlib import Path

from devsecops_scanner.sca.scanner import scan_manifests


FIXTURES = Path(__file__).parent / "fixtures"


def test_requirements_known_cves_are_reported():
    findings = scan_manifests([
        (FIXTURES / "requirements.txt", "requirements.txt"),
    ])
    assert {item.cve for item in findings} == {
        "CVE-2018-18074", "CVE-2021-33503",
    }
    assert all(item.category == "SCA" for item in findings)


def test_pyproject_dependency_manifest(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\ndependencies = ["requests==2.19.1"]\n'
        '[project.optional-dependencies]\ntest = ["urllib3==1.26.4"]\n',
        encoding="utf-8",
    )
    findings = scan_manifests([(manifest, "pyproject.toml")])
    assert len(findings) == 2


def test_sca_detects_affected_versions_allowed_by_constraints(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests>=2.18,<2.20\n", encoding="utf-8")
    findings = scan_manifests([(manifest, "requirements.txt")])
    assert [item.cve for item in findings] == ["CVE-2018-18074"]


def test_poetry_caret_constraint_is_not_treated_as_an_exact_pin(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.19.1"\n',
        encoding="utf-8",
    )
    findings = scan_manifests([(manifest, "pyproject.toml")])
    assert [item.cve for item in findings] == ["CVE-2018-18074"]


def test_custom_advisory_database_is_validated(tmp_path):
    advisory = tmp_path / "advisories.json"
    advisory.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    try:
        scan_manifests([], advisory)
    except ValueError as error:
        assert "JSON array" in str(error)
    else:
        raise AssertionError("invalid advisory data should be rejected")
