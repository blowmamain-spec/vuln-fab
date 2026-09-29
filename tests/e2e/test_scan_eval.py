import json
import os
import shutil
import time
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from vulnfab.cli import app
from vulnfab.core.engine import ScanOptions, scan

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "eval_repo"
SCHEMA = json.loads((ROOT / "docs" / "schema" / "scan-output.schema.json").read_text())
SNAPSHOT = Path(__file__).parent / "snapshots" / "eval_repo.json"


def _normalised(data: dict) -> dict:  # type: ignore[type-arg]
    data = json.loads(json.dumps(data))
    data["target"]["path"] = "<root>"
    return data


def _run_json(path: Path, *args: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    result = CliRunner().invoke(app, ["scan", str(path), "--format", "json", *args])
    return result.exit_code, json.loads(result.output)


def test_finds_eval_with_correct_lines() -> None:
    result = scan(FIXTURE)
    found = sorted((f.file, f.line) for f in result.findings)
    # eval("1 + 1") is a literal argument and is intentionally not reported
    assert found == [("app.py", 6), ("app.py", 12), ("syntax_error.py", 2)]
    assert all(f.rule_id == "py-eval" for f in result.findings)
    assert result.coverage.syntax_errors == ["syntax_error.py"]
    assert result.stacks == ["generic"]


def test_fingerprints_unique_and_stable_under_line_shift(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    shutil.copytree(FIXTURE, repo)
    before = {f.fingerprint for f in scan(repo).findings}
    assert len(before) == 3
    app_py = repo / "app.py"
    app_py.write_text("# added\n\n\n" + app_py.read_text())
    after = {f.fingerprint for f in scan(repo).findings}
    assert before == after


def test_json_output_validates_and_matches_snapshot() -> None:
    code, data = _run_json(FIXTURE)
    assert code == 0
    jsonschema.validate(data, SCHEMA)
    normalised = _normalised(data)
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(normalised, indent=2, sort_keys=True) + "\n")
    assert normalised == json.loads(SNAPSHOT.read_text())


def test_console_output_mentions_coverage() -> None:
    result = CliRunner().invoke(app, ["scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "py-eval" in result.output
    assert "Coverage & limitations" in result.output


def test_fail_on_exit_code() -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(FIXTURE), "--fail-on", "high"]).exit_code == 1
    assert runner.invoke(app, ["scan", str(FIXTURE), "--fail-on", "critical"]).exit_code == 0


def test_usage_errors() -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(FIXTURE / "nope")]).exit_code == 2
    assert runner.invoke(app, ["scan", str(FIXTURE), "--stack", "nope"]).exit_code == 2


def test_min_confidence_hides_and_reports(tmp_path: Path) -> None:
    code, data = _run_json(FIXTURE, "--min-confidence", "high")
    assert code == 0
    assert data["findings"] == []
    assert data["coverage"]["hidden_low_confidence"] == 3


def test_pathological_files_do_not_crash_or_hang(tmp_path: Path) -> None:
    repo = tmp_path / "patho"
    repo.mkdir()
    (repo / "ok.py").write_text("eval(x)\n")
    (repo / "deep.py").write_text("x = " + "(" * 20000 + "1" + ")" * 20000 + "\n")
    (repo / "big.py").write_text("x = 1\n" * 300_000)  # ~1.8 MB
    (repo / "blob.py").write_bytes(b"\x00\xff" * 4096)
    (repo / "oneline.js").write_text("var a=" + "+".join(["1"] * 50_000) + ";\n")
    start = time.monotonic()
    code, data = _run_json(repo)
    assert time.monotonic() - start < 30
    assert code == 0
    jsonschema.validate(data, SCHEMA)
    assert [f["file"] for f in data["findings"]] == ["ok.py"]
    reasons = {s["file"]: s["reason"] for s in data["coverage"]["files_skipped"]}
    assert reasons == {
        "big.py": "too_large",
        "blob.py": "binary",
        "deep.py": "parse_error",
        "oneline.js": "parse_error",  # 50k-term chain exceeds the AST depth limit
    }


def test_options_max_file_kb(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("eval(x)\n" * 200)
    result = scan(tmp_path, ScanOptions(max_file_bytes=100))
    assert result.findings == []
    assert result.coverage.files_skipped[0].reason == "too_large"
