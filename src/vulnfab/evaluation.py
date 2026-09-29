"""Benchmark evaluation against ground truth (docs/spec.md section 8)."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TOLERANCE = 3


class EvaluationError(Exception):
    pass


@dataclass(frozen=True)
class TruthItem:
    id: str
    kind: str  # vulnerable | decoy
    file: str
    line_start: int
    line_end: int
    cls: str
    tier: str | None
    in_scope: bool


@dataclass(frozen=True)
class FindingRef:
    rule_id: str
    file: str
    line: int
    end_line: int
    fingerprint: str
    tier: str | None

    @property
    def cls(self) -> str:
        return finding_class(self.rule_id)


# Taint rules use short class names; pattern rules (and the ground-truth labels) use long ones.
CLASS_ALIASES = {
    "codei": "dynamic-eval",
    "cmdi": "cmd-injection",
    "deser": "deserialization",
    "pathtrav": "path-traversal",
}


def finding_class(rule_id: str) -> str:
    """``sb-rls-missing`` -> ``rls-missing`` (strip the stack prefix)."""
    cls = rule_id.split("-", 1)[1] if "-" in rule_id else rule_id
    return CLASS_ALIASES.get(cls, cls)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    labels_total: int = 0  # in-scope vulnerable labels
    labels_hit: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        return self.labels_hit / self.labels_total if self.labels_total else None


@dataclass
class Report:
    target: str
    overall: Counts = field(default_factory=Counts)
    by_class: dict[str, Counts] = field(default_factory=dict)
    by_tier: dict[str, Counts] = field(default_factory=dict)
    missed: list[TruthItem] = field(default_factory=list)
    decoy_hits: list[tuple[FindingRef, TruthItem]] = field(default_factory=list)
    unreviewed: list[FindingRef] = field(default_factory=list)
    out_of_scope_hits: list[FindingRef] = field(default_factory=list)
    duplicates: int = 0


def load_truth(path: Path) -> tuple[str, list[TruthItem]]:
    data = json.loads(path.read_text())
    items = [
        TruthItem(
            id=i["id"],
            kind=i["kind"],
            file=i["file"],
            line_start=i["line_start"],
            line_end=i["line_end"],
            cls=i["class"],
            tier=i.get("tier"),
            in_scope=i.get("in_scope", True),
        )
        for i in data["items"]
    ]
    return str(data["target"]), items


def load_verdicts(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    data = json.loads(path.read_text())
    out: dict[str, str] = {}
    for fingerprint, entry in data.get("verdicts", {}).items():
        verdict = entry["verdict"] if isinstance(entry, dict) else entry
        if verdict not in {"tp", "fp", "dup"}:
            raise EvaluationError(f"bad verdict {verdict!r} for {fingerprint}")
        out[fingerprint] = verdict
    return out


def load_findings(path: Path) -> list[FindingRef]:
    data: Any = json.loads(path.read_text())
    raw = data["findings"] if isinstance(data, dict) else data
    findings: list[FindingRef] = []
    seen: set[str] = set()
    for f in raw:
        fingerprint = f.get("fingerprint") or ""
        if not fingerprint:
            raise EvaluationError(
                f"finding without fingerprint: {f.get('rule_id')} {f.get('file')}"
            )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            FindingRef(
                rule_id=f["rule_id"],
                file=f["file"],
                line=f["line"],
                end_line=f.get("end_line", f["line"]),
                fingerprint=fingerprint,
                tier=f.get("tier"),
            )
        )
    return findings


def _overlap(f: FindingRef, t: TruthItem, tolerance: int) -> bool:
    return f.line <= t.line_end + tolerance and f.end_line >= t.line_start - tolerance


def _best_match(f: FindingRef, truth: list[TruthItem]) -> TruthItem | None:
    candidates = [t for t in truth if t.file == f.file and t.cls == f.cls]
    for tolerance in (0, TOLERANCE):  # strict overlap wins over tolerant overlap
        hits = [t for t in candidates if _overlap(f, t, tolerance)]
        if hits:
            # prefer vulnerable labels, then the closest start line
            hits.sort(key=lambda t: (t.kind != "vulnerable", abs(t.line_start - f.line)))
            return hits[0]
    return None


def evaluate(
    target: str,
    truth: list[TruthItem],
    findings: list[FindingRef],
    verdicts: dict[str, str] | None = None,
) -> Report:
    verdicts = verdicts or {}
    report = Report(target=target)
    hit_labels: set[str] = set()

    def counts(cls: str, tier: str | None) -> list[Counts]:
        out = [report.overall, report.by_class.setdefault(cls, Counts())]
        if tier:
            out.append(report.by_tier.setdefault(tier, Counts()))
        return out

    for t in truth:
        if t.kind == "vulnerable" and t.in_scope:
            for c in counts(t.cls, t.tier):
                c.labels_total += 1

    for f in findings:
        match = _best_match(f, truth)
        if match is None:
            verdict = verdicts.get(f.fingerprint)
            if verdict is None:
                report.unreviewed.append(f)
            elif verdict == "dup":
                report.duplicates += 1
            else:
                for c in counts(f.cls, f.tier):
                    if verdict == "tp":
                        c.tp += 1
                    else:
                        c.fp += 1
            continue
        if match.kind == "decoy":
            report.decoy_hits.append((f, match))
            for c in counts(f.cls, match.tier or f.tier):
                c.fp += 1
        elif not match.in_scope:
            report.out_of_scope_hits.append(f)
        elif match.id in hit_labels:
            report.duplicates += 1
        else:
            hit_labels.add(match.id)
            for c in counts(f.cls, match.tier or f.tier):
                c.tp += 1
                c.labels_hit += 1

    report.missed = [
        t for t in truth if t.kind == "vulnerable" and t.in_scope and t.id not in hit_labels
    ]
    return report


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def format_markdown(report: Report) -> str:
    lines = [f"# Evaluasi: {report.target}", ""]
    o = report.overall
    lines += [
        f"- Precision: **{_pct(o.precision)}** (TP {o.tp}, FP {o.fp})",
        f"- Recall: **{_pct(o.recall)}** ({o.labels_hit}/{o.labels_total} label dalam scope)",
        f"- Decoy terpicu: {len(report.decoy_hits)} · Duplikat: {report.duplicates}"
        f" · Di luar scope: {len(report.out_of_scope_hits)}"
        f" · Belum di-review: {len(report.unreviewed)}",
        "",
        "| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(report.by_class):
        c = report.by_class[name]
        lines.append(
            f"| {name} | {c.tp} | {c.fp} | {_pct(c.precision)} | {c.labels_total} | "
            f"{c.labels_hit} | {_pct(c.recall)} |"
        )
    if report.by_tier:
        lines += [
            "",
            "| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name in sorted(report.by_tier):
            c = report.by_tier[name]
            lines.append(
                f"| {name} | {c.tp} | {c.fp} | {_pct(c.precision)} | {c.labels_total} | "
                f"{c.labels_hit} | {_pct(c.recall)} |"
            )
    if report.missed:
        lines += ["", "## Terlewat (false negative)"]
        lines += [f"- {t.id} `{t.cls}` {t.file}:{t.line_start}-{t.line_end}" for t in report.missed]
    if report.decoy_hits:
        lines += ["", "## Decoy terpicu (false positive)"]
        lines += [f"- {f.rule_id} {f.file}:{f.line} (decoy {t.id})" for f, t in report.decoy_hits]
    if report.unreviewed:
        lines += ["", "## Belum di-review (butuh verdict)"]
        lines += [f"- `{f.fingerprint}` {f.rule_id} {f.file}:{f.line}" for f in report.unreviewed]
    return "\n".join(lines) + "\n"


def summarize_by_rule(findings: list[FindingRef]) -> dict[str, int]:
    counter: dict[str, int] = defaultdict(int)
    for f in findings:
        counter[f.rule_id] += 1
    return dict(counter)
