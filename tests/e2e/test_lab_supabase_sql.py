"""Gate for the Supabase (SQL/config) half of the lab (WP-3.8); TS classes come in phase 4."""

from __future__ import annotations

import json
import time
from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence, to_jsonable
from vulnfab.evaluation import FindingRef, evaluate, load_truth

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "benchmarks" / "labs" / "supabase-vuln"
TRUTH = ROOT / "benchmarks" / "truth" / "supabase-vuln.json"

SB_CLASSES = {
    "rls-missing", "policy-true", "policy-anon-write", "policy-user-metadata", "policy-no-uid",
    "definer-no-path", "view-no-invoker", "grant-broad", "default-priv", "dynamic-sql",
    "storage-public", "storage-policy", "seed-secret", "config-signup",
}  # fmt: skip


def _report():  # type: ignore[no-untyped-def]
    start = time.monotonic()
    result = scan(LAB, ScanOptions(min_confidence=Confidence.LOW))
    elapsed = time.monotonic() - start
    target, truth = load_truth(TRUTH)
    truth = [t for t in truth if t.cls in SB_CLASSES]
    findings = [
        FindingRef(f.rule_id, f.file, f.line, f.end_line, f.fingerprint, f.tier)
        for f in result.findings
        if f.rule_id.startswith("sb-")
    ]
    return evaluate(target, truth, findings), result, elapsed


def test_supabase_half_meets_gate() -> None:
    report, result, elapsed = _report()
    assert report.decoy_hits == [], [(f.rule_id, f.file, f.line) for f, _ in report.decoy_hits]
    assert report.missed == [], [(t.id, t.cls) for t in report.missed]
    assert report.unreviewed == [], [(f.rule_id, f.file, f.line) for f in report.unreviewed]
    assert report.overall.precision == 1.0 and report.overall.recall == 1.0
    assert elapsed < 10, f"lab scan took {elapsed:.1f}s"
    assert result.coverage.unresolved == []


def test_out_of_scope_business_idor_is_not_reported_as_a_finding() -> None:
    _, result, _ = _report()
    assert not [f for f in result.findings if "business-idor" in f.rule_id]


def test_assumptions_are_reported() -> None:
    _, result, _ = _report()
    text = " ".join(result.coverage.assumptions)
    assert "migrations only" in text and "default privileges" in text


def test_findings_are_explained() -> None:
    _, result, _ = _report()
    by_rule = {f.rule_id: f for f in result.findings if f.rule_id.startswith("sb-")}
    rls = by_rule["sb-rls-missing"]
    assert "Row Level Security" in rls.message and rls.trace and rls.snippet
    assert json.dumps(to_jsonable(rls))  # serialisable


def test_rls_missing_points_at_the_disable_statement() -> None:
    _, result, _ = _report()
    disable = [
        f for f in result.findings
        if f.rule_id == "sb-rls-missing" and f.file.endswith("storage_and_fixes.sql")
    ]  # fmt: skip
    assert [f.line for f in disable] == [26]
    assert "disable row level security" in disable[0].snippet.lower()
