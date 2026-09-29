import json
from pathlib import Path

import pytest

from vulnfab.evaluation import (
    EvaluationError,
    FindingRef,
    TruthItem,
    evaluate,
    finding_class,
    format_markdown,
    load_findings,
    load_verdicts,
)


def T(id: str, kind: str, start: int, end: int, cls: str = "rls-missing", **kw) -> TruthItem:  # noqa: N802
    return TruthItem(
        id,
        kind,
        kw.get("file", "a.sql"),
        start,
        end,
        cls,
        kw.get("tier", "A"),
        kw.get("in_scope", True),
    )


def F(
    fp: str, line: int, rule: str = "sb-rls-missing", file: str = "a.sql", end: int | None = None
) -> FindingRef:  # noqa: N802
    return FindingRef(rule, file, line, end or line, fp, "A")


TRUTH = [
    T("T001", "vulnerable", 10, 12),
    T("T002", "vulnerable", 30, 30),
    T("D001", "decoy", 20, 22),
    T("T003", "vulnerable", 50, 50, cls="policy-true", in_scope=False),
]


def test_finding_class() -> None:
    assert finding_class("sb-rls-missing") == "rls-missing"
    assert finding_class("ts-table-no-rls") == "table-no-rls"
    assert finding_class("nodash") == "nodash"


def test_tp_fn_and_decoy() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 11), F("f2", 21)])
    assert rep.overall.tp == 1 and rep.overall.fp == 1
    assert rep.overall.labels_total == 2 and rep.overall.labels_hit == 1
    assert [t.id for t in rep.missed] == ["T002"]
    assert [t.id for _, t in rep.decoy_hits] == ["D001"]
    assert rep.overall.precision == 0.5 and rep.overall.recall == 0.5


def test_strict_overlap_beats_tolerance() -> None:
    truth = [T("T001", "vulnerable", 10, 12), T("D001", "decoy", 15, 17)]
    rep = evaluate("x", truth, [F("f1", 12)])  # within tolerance of D001, strictly in T001
    assert rep.overall.tp == 1 and rep.decoy_hits == []


def test_tolerance_applies_when_no_strict_overlap() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 33)])  # 3 lines after T002
    assert rep.overall.tp == 1
    rep = evaluate("x", TRUTH, [F("f1", 34)])  # outside tolerance
    assert rep.overall.tp == 0 and len(rep.unreviewed) == 1


def test_class_and_file_must_match() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 11, rule="sb-policy-true"), F("f2", 11, file="b.sql")])
    assert rep.overall.tp == 0
    assert len(rep.unreviewed) == 2


def test_duplicates_are_not_false_positives() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 10), F("f2", 12)])
    assert rep.overall.tp == 1 and rep.overall.fp == 0 and rep.duplicates == 1


def test_out_of_scope_is_neutral() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 50, rule="sb-policy-true")])
    assert rep.overall.tp == 0 and rep.overall.fp == 0
    assert len(rep.out_of_scope_hits) == 1 and rep.unreviewed == []


def test_unlabeled_findings_need_verdicts() -> None:
    findings = [F("u1", 100), F("u2", 101), F("u3", 102), F("u4", 103)]
    rep = evaluate("x", TRUTH, findings, {"u1": "tp", "u2": "fp", "u3": "dup"})
    assert rep.overall.tp == 1 and rep.overall.fp == 1 and rep.duplicates == 1
    assert [f.fingerprint for f in rep.unreviewed] == ["u4"]


def test_by_class_and_tier() -> None:
    rep = evaluate("x", TRUTH, [F("f1", 11)])
    assert rep.by_class["rls-missing"].labels_total == 2
    assert rep.by_class["rls-missing"].recall == 0.5
    assert rep.by_tier["A"].tp == 1


def test_markdown_report_lists_problems() -> None:
    text = format_markdown(evaluate("x", TRUTH, [F("f2", 21), F("u", 100)]))
    assert "Terlewat" in text and "T001" in text
    assert "Decoy terpicu" in text and "D001" in text
    assert "Belum di-review" in text


def test_loaders(tmp_path: Path) -> None:
    findings = tmp_path / "f.json"
    findings.write_text(
        json.dumps(
            {
                "findings": [
                    {"rule_id": "sb-x", "file": "a", "line": 1, "fingerprint": "a"},
                    {"rule_id": "sb-x", "file": "a", "line": 1, "fingerprint": "a"},
                ]
            }
        )
    )
    assert len(load_findings(findings)) == 1
    findings.write_text(json.dumps([{"rule_id": "sb-x", "file": "a", "line": 1}]))
    with pytest.raises(EvaluationError):
        load_findings(findings)
    verdicts = tmp_path / "v.json"
    verdicts.write_text(json.dumps({"verdicts": {"a": {"verdict": "tp"}, "b": "fp"}}))
    assert load_verdicts(verdicts) == {"a": "tp", "b": "fp"}
    verdicts.write_text(json.dumps({"verdicts": {"a": "maybe"}}))
    with pytest.raises(EvaluationError):
        load_verdicts(verdicts)
    assert load_verdicts(None) == {}


def _findings_from_truth(kind: str) -> list[dict[str, object]]:
    truth = json.loads((ROOT / "benchmarks" / "truth" / "supabase-vuln.json").read_text())
    out = []
    for item in truth["items"]:
        if item["kind"] == kind:
            out.append(
                {
                    "rule_id": "x-" + item["class"],
                    "file": item["file"],
                    "line": item["line_start"],
                    "end_line": item["line_end"],
                    "fingerprint": "fp-" + item["id"],
                    "tier": item["tier"],
                }
            )
    return out


def _run(findings: list[dict[str, object]], tmp_path: Path, *extra: str) -> tuple[int, str]:
    import subprocess
    import sys

    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": findings}))
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "benchmarks" / "evaluate.py"),
            "--target",
            "supabase-vuln",
            "--findings",
            str(path),
            *extra,
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


ROOT = Path(__file__).resolve().parents[2]


def test_cli_perfect_scan_on_real_truth(tmp_path: Path) -> None:
    code, out = _run(
        _findings_from_truth("vulnerable"),
        tmp_path,
        "--min-recall",
        "1.0",
        "--min-precision",
        "1.0",
        "--max-decoy-hits",
        "0",
    )
    assert code == 0, out
    assert "Recall: **100%**" in out


def test_cli_decoy_hit_fails_gate(tmp_path: Path) -> None:
    findings = _findings_from_truth("vulnerable") + _findings_from_truth("decoy")[:1]
    code, out = _run(findings, tmp_path, "--max-decoy-hits", "0")
    assert code == 1
    assert "decoy hits" in out


def test_cli_unreviewed_findings_fail(tmp_path: Path) -> None:
    extra = {"rule_id": "sb-rls-missing", "file": "nope.sql", "line": 1, "fingerprint": "zzz"}
    code, out = _run([extra], tmp_path)
    assert code == 1 and "without verdict" in out
    code, _ = _run([extra], tmp_path, "--allow-unreviewed")
    assert code == 0
