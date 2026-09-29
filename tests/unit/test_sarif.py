"""SARIF 2.1.0 output validates against the official schema and keeps the essentials."""
# ruff: noqa: E501, E741

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence, Finding, Severity, TraceStep
from vulnfab.core.report import Coverage, ScanResult
from vulnfab.reporters import sarif

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/schema/sarif-schema-2.1.0.json").read_text()
)


def validate(document: dict) -> None:  # type: ignore[type-arg]
    jsonschema.Draft4Validator(SCHEMA).validate(document)


def finding(**kw) -> Finding:  # type: ignore[no-untyped-def]
    base = dict(
        rule_id="tpy-sqli",
        title="SQL injection",
        cwe=("CWE-89",),
        owasp="A03:2021",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tier="A",
        file="app/views.py",
        line=12,
        end_line=12,
        snippet="cursor.execute(q)",
        fix="Use parameters.",
        fingerprint="abc123",
        message="Untrusted input reaches SQL.",
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def result_of(*findings: Finding) -> ScanResult:
    return ScanResult("repo", ["generic"], list(findings), Coverage(files_scanned=3))


def test_empty_result_is_valid() -> None:
    doc = sarif.to_sarif_dict(result_of())
    validate(doc)
    assert doc["runs"][0]["results"] == []


def test_finding_maps_level_fingerprint_and_rule_metadata() -> None:
    doc = sarif.to_sarif_dict(result_of(finding()))
    validate(doc)
    run = doc["runs"][0]
    (res,) = run["results"]
    assert res["level"] == "error" and res["ruleId"] == "tpy-sqli" and res["ruleIndex"] == 0
    assert res["partialFingerprints"] == {"vulnfab/v1": "abc123"}
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 12 and region["snippet"]["text"] == "cursor.execute(q)"
    rule = run["tool"]["driver"]["rules"][0]
    assert (
        "CWE-89" in rule["properties"]["tags"] and rule["properties"]["security-severity"] == "8.0"
    )
    assert rule["help"]["text"] == "Use parameters."


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_levels(severity: Severity, level: str) -> None:
    doc = sarif.to_sarif_dict(result_of(finding(severity=severity)))
    validate(doc)
    assert doc["runs"][0]["results"][0]["level"] == level


def test_trace_becomes_code_flow_in_order() -> None:
    trace = (
        TraceStep("a.py", 3, "source", "request.args"),
        TraceStep("a.py", 4, "propagate", "q = …"),
        TraceStep("b.py", 9, "sink", "call to execute"),
    )
    doc = sarif.to_sarif_dict(result_of(finding(trace=trace)))
    validate(doc)
    flow = doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [l["location"]["physicalLocation"]["region"]["startLine"] for l in flow] == [3, 4, 9]
    assert flow[0]["location"]["message"]["text"].startswith("source")


def test_two_rules_get_stable_indexes_and_dedupe() -> None:
    a = finding()
    b = finding(
        rule_id="dj-debug-true", title="DEBUG", file="s.py", line=1, end_line=1, fingerprint="f2"
    )
    c = finding(line=30, end_line=30, fingerprint="f3")
    doc = sarif.to_sarif_dict(result_of(a, b, c))
    validate(doc)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["dj-debug-true", "tpy-sqli"] or len(rules) == 2
    for res in doc["runs"][0]["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


def test_unicode_and_markup_in_snippet_survive_json() -> None:
    doc = sarif.to_sarif_dict(result_of(finding(snippet="<script>alert('é')</script>")))
    validate(doc)
    text = sarif.render(result_of(finding(snippet="<script>alert('é')</script>")))
    assert json.loads(text)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
        "snippet"
    ]["text"].startswith("<script>")


def test_real_scan_output_validates(tmp_path: Path) -> None:
    (tmp_path / "manage.py").write_text("import django\n")
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj/settings.py").write_text(
        "DEBUG = True\nSECRET_KEY = 'x'\nINSTALLED_APPS = []\n"
    )
    (tmp_path / "proj/views.py").write_text(
        "import os\n\ndef v(request):\n    os.system('ls ' + request.GET['d'])\n"
    )
    result = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW))
    assert result.findings
    doc = sarif.to_sarif_dict(result)
    validate(doc)
    flows = [r for r in doc["runs"][0]["results"] if "codeFlows" in r]
    assert flows, "the command-injection finding should carry a code flow"


def test_cli_writes_valid_sarif(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from vulnfab.cli import app

    (tmp_path / "a.py").write_text("eval(input())\n")
    out = tmp_path / "out.sarif"
    r = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--format", "sarif", "-o", str(out), "--min-confidence", "low"]
    )
    assert r.exit_code == 0, r.output
    validate(json.loads(out.read_text()))
