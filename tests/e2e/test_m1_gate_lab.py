"""Gate M1 on the supabase-vuln lab (WP-4.7): the whole pipeline against ground truth."""

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


def _report():  # type: ignore[no-untyped-def]
    start = time.monotonic()
    result = scan(LAB, ScanOptions(min_confidence=Confidence.LOW))
    elapsed = time.monotonic() - start
    target, truth = load_truth(TRUTH)
    findings = [
        FindingRef(f.rule_id, f.file, f.line, f.end_line, f.fingerprint, f.tier)
        for f in result.findings
    ]
    return evaluate(target, truth, findings), result, elapsed


def test_m1_gate() -> None:
    report, result, elapsed = _report()
    assert report.decoy_hits == [], [(f.rule_id, f.file, f.line) for f, _ in report.decoy_hits]
    assert report.missed == [], [(t.id, t.cls) for t in report.missed]
    assert report.unreviewed == [], [(f.rule_id, f.file, f.line) for f in report.unreviewed]
    tier_a = report.by_tier["A"]
    assert (tier_a.recall or 0) >= 0.9 and (tier_a.precision or 0) >= 0.9
    assert (report.overall.precision or 0) >= 0.9
    assert elapsed < 10, f"lab scan took {elapsed:.1f}s"
    assert result.coverage.unresolved == []
    assert result.stacks == ["generic", "supabase", "typescript"]


def test_business_idor_is_out_of_scope_and_not_reported() -> None:
    _, result, _ = _report()
    assert not [f for f in result.findings if "business-idor" in f.rule_id]


def test_assumptions_are_reported() -> None:
    _, result, _ = _report()
    text = " ".join(result.coverage.assumptions)
    assert "migrations only" in text and "default privileges" in text


def test_cross_check_findings_have_code_and_schema_traces() -> None:
    _, result, _ = _report()
    hit = next(f for f in result.findings if f.rule_id == "ts-table-no-rls")
    kinds = [s.kind for s in hit.trace]
    assert kinds == ["source", "schema"]
    assert hit.trace[0].file.endswith("audit.tsx")
    assert hit.trace[1].file.endswith("20240101000000_init.sql")
    assert "audit_log" in hit.message and json.dumps(to_jsonable(hit))


def test_generic_duplicates_are_superseded() -> None:
    _, result, _ = _report()
    ids = {f.rule_id for f in result.findings}
    assert not ids & {"js-eval", "js-exec", "js-dangerous-html", "js-function-constructor"}


def test_secrets_are_redacted_in_snippets() -> None:
    _, result, _ = _report()
    secret = next(f for f in result.findings if f.rule_id == "sec-secret-hardcoded")
    assert "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a" not in secret.snippet


def test_rls_missing_points_at_the_disable_statement() -> None:
    _, result, _ = _report()
    disable = [
        f
        for f in result.findings
        if f.rule_id == "sb-rls-missing" and f.file.endswith("storage_and_fixes.sql")
    ]
    assert [f.line for f in disable] == [26]
    assert "disable row level security" in disable[0].snippet.lower()
