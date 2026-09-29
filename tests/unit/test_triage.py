"""`vulnfab triage` stores verdicts that change the evaluator's result (WP-9.2)."""
# ruff: noqa: E501

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnfab.cli import app
from vulnfab.evaluation import evaluate, load_findings, load_truth, load_verdicts

runner = CliRunner()


def make_findings(tmp_path: Path) -> Path:
    doc = {
        "findings": [
            {
                "rule_id": "tpy-sqli",
                "file": "a.py",
                "line": 3,
                "end_line": 3,
                "fingerprint": "f1",
                "tier": "A",
                "severity": "high",
            },
            {
                "rule_id": "tpy-sqli",
                "file": "a.py",
                "line": 30,
                "end_line": 30,
                "fingerprint": "f2",
                "tier": "A",
                "severity": "high",
            },
        ]
    }
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(doc))
    return path


def make_truth(tmp_path: Path) -> Path:
    truth = {
        "target": "t",
        "items": [
            {
                "id": "T1",
                "kind": "vulnerable",
                "file": "a.py",
                "line_start": 3,
                "line_end": 3,
                "class": "sqli",
                "tier": "A",
                "in_scope": True,
            }
        ],
    }
    path = tmp_path / "truth.json"
    path.write_text(json.dumps(truth))
    return path


def test_set_list_and_clear(tmp_path: Path) -> None:
    findings, verdicts = make_findings(tmp_path), tmp_path / "v.json"
    out = runner.invoke(app, ["triage", "list", str(findings), "-f", str(verdicts)])
    assert "2 finding(s) without a verdict" in out.output
    assert (
        runner.invoke(
            app, ["triage", "set", "f2", "-v", "fp", "-n", "constant", "-f", str(verdicts)]
        ).exit_code
        == 0
    )
    out = runner.invoke(app, ["triage", "list", str(findings), "-f", str(verdicts)])
    assert "f2" not in out.output and "1 finding(s)" in out.output
    assert runner.invoke(app, ["triage", "clear", "f2", "-f", str(verdicts)]).exit_code == 0
    assert (
        "2 finding(s)"
        in runner.invoke(app, ["triage", "list", str(findings), "-f", str(verdicts)]).output
    )


def test_bad_verdict_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["triage", "set", "f1", "-v", "maybe", "-f", str(tmp_path / "v.json")]
    )
    assert result.exit_code == 2


def test_verdicts_change_the_evaluation(tmp_path: Path) -> None:
    findings, truth = make_findings(tmp_path), make_truth(tmp_path)
    verdicts = tmp_path / "v.json"
    _, items = load_truth(truth)
    before = evaluate("t", items, load_findings(findings), load_verdicts(verdicts))
    assert [f.fingerprint for f in before.unreviewed] == ["f2"]
    runner.invoke(app, ["triage", "set", "f2", "-v", "fp", "-f", str(verdicts)])
    after = evaluate("t", items, load_findings(findings), load_verdicts(verdicts))
    assert after.unreviewed == [] and after.overall.fp == 1 and after.overall.tp == 1
    runner.invoke(app, ["triage", "set", "f2", "-v", "tp", "-f", str(verdicts)])
    final = evaluate("t", items, load_findings(findings), load_verdicts(verdicts))
    assert final.overall.fp == 0 and final.overall.tp == 2
