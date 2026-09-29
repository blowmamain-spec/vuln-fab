"""CI gates: vulnfab scans itself cleanly, and each lab keeps its regression gate (WP-9.4)."""
# ruff: noqa: E501

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence
from vulnfab.core.report import to_json_dict
from vulnfab.evaluation import evaluate, load_findings, load_truth, load_verdicts

ROOT = Path(__file__).resolve().parents[2]
LABS = ["supabase-vuln", "django-vuln", "laravel-vuln"]
# the gate for each lab is evaluated at the confidence the run_all benchmark uses
GATE_CONFIDENCE = {"supabase-vuln": Confidence.LOW}


def test_vulnfab_source_is_clean_under_vulnfab() -> None:
    result = scan(ROOT, ScanOptions(min_confidence=Confidence.LOW))
    assert [(f.rule_id, f.file, f.line) for f in result.findings] == []


@pytest.mark.parametrize("lab", LABS)
def test_lab_truth_is_up_to_date(lab: str) -> None:
    done = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks/labs/truth_from_markers.py"), lab, "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("lab", LABS)
def test_lab_gate(lab: str, tmp_path: Path) -> None:
    import json

    result = scan(
        ROOT / "benchmarks/labs" / lab,
        ScanOptions(min_confidence=GATE_CONFIDENCE.get(lab, Confidence.MEDIUM)),
    )
    findings_file = tmp_path / "f.json"
    findings_file.write_text(json.dumps(to_json_dict(result)))
    target, truth = load_truth(ROOT / "benchmarks/truth" / f"{lab}.json")
    classes = {t.cls for t in truth}
    findings = [f for f in load_findings(findings_file) if f.cls in classes]
    report = evaluate(
        target, truth, findings, load_verdicts(ROOT / "benchmarks/verdicts" / f"{lab}.json")
    )
    assert report.missed == [], [(t.id, t.cls) for t in report.missed]
    assert report.decoy_hits == [], [(f.rule_id, f.file, f.line) for f, _ in report.decoy_hits]
    assert report.unreviewed == [], [(f.rule_id, f.file, f.line) for f in report.unreviewed]
    assert report.overall.fp == 0
