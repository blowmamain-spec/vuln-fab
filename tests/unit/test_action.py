"""GitHub Action and pre-commit hook: structure, and the run script's behaviour (WP-10.5)."""
# ruff: noqa: E501

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SARIF_SCHEMA = json.loads((ROOT / "docs/schema/sarif-schema-2.1.0.json").read_text())


def test_action_yml_is_a_well_formed_composite_action() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    assert {"path", "fail-on", "min-confidence", "since", "upload-sarif"} <= set(action["inputs"])
    steps = action["runs"]["steps"]
    assert all("shell" in s for s in steps if "run" in s)
    ids = [s.get("id") for s in steps]
    assert "scan" in ids
    upload = next(s for s in steps if "upload-sarif" in str(s.get("uses", "")))
    assert "steps.scan.outputs.exit-code" in upload["if"]
    assert any("exit ${{ steps.scan.outputs.exit-code }}" in s.get("run", "") for s in steps)
    for name, spec in action["inputs"].items():
        assert spec.get("description"), name


def test_pre_commit_hooks_are_defined() -> None:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    assert {h["id"] for h in hooks} == {"vulnfab", "vulnfab-changed"}
    for hook in hooks:
        assert hook["entry"].startswith("vulnfab scan") and hook["pass_filenames"] is False


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import os\n\ndef v(request):\n    os.system(request.GET['x'])\n"
    )
    return tmp_path


def run_script(project: Path, tmp_path: Path, **env: str) -> tuple[int, dict[str, str], Path]:
    output = tmp_path / "gh_output.txt"
    output.write_text("")
    full_env = {
        **os.environ,
        "VULNFAB_PATH": str(project),
        "VULNFAB_SARIF": str(tmp_path / "out.sarif"),
        "GITHUB_OUTPUT": str(output),
        "VULNFAB_CACHE_DIR": str(tmp_path / "cache"),
        **env,
    }
    vulnfab = shutil.which("vulnfab")
    assert vulnfab, "vulnfab must be installed for this test"
    done = subprocess.run(
        ["bash", str(ROOT / "scripts/action-run.sh")],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
    return done.returncode, outputs, tmp_path / "out.sarif"


def test_script_uploads_valid_sarif_and_reports_findings_exit_code(
    project: Path, tmp_path: Path
) -> None:
    code, outputs, sarif = run_script(project, tmp_path, VULNFAB_FAIL_ON="high")
    assert code == 0  # the step never fails by itself, so the SARIF upload can run
    assert outputs["exit-code"] == "1"  # findings at/above --fail-on
    document = json.loads(sarif.read_text())
    jsonschema.Draft4Validator(SARIF_SCHEMA).validate(document)
    assert document["runs"][0]["results"]


def test_script_without_fail_on_never_fails(project: Path, tmp_path: Path) -> None:
    _, outputs, sarif = run_script(project, tmp_path)
    assert outputs["exit-code"] == "0" and sarif.is_file()


def test_script_reports_usage_errors(tmp_path: Path) -> None:
    _, outputs, _ = run_script(tmp_path / "missing", tmp_path)
    assert outputs["exit-code"] == "2"


def test_script_honours_min_confidence_and_extra_args(project: Path, tmp_path: Path) -> None:
    _, outputs, sarif = run_script(
        project, tmp_path, VULNFAB_MIN_CONF="high", VULNFAB_EXTRA_ARGS="--no-cache --jobs 2"
    )
    assert outputs["exit-code"] == "0"
    assert json.loads(sarif.read_text())["runs"][0]["results"] == []
