"""Scoring, deduplication and supersession (docs/spec.md section 4)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from vulnfab.core.models import Confidence, Finding, Severity


def adjust(finding: Finding) -> Finding:
    """Apply the automatic confidence/severity adjustments."""
    confidence = finding.confidence
    severity = finding.severity
    if finding.unresolved_hops:
        confidence = confidence.lowered(finding.unresolved_hops)
    if finding.tier == "B" and confidence is Confidence.HIGH:
        confidence = Confidence.MEDIUM  # tier B is pattern-based, never "high"
    if finding.tier == "C":
        severity = Severity.INFO
        confidence = Confidence.LOW
    if severity is finding.severity and confidence is finding.confidence:
        return finding
    return replace(finding, severity=severity, confidence=confidence)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.end_line, f.snippet)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def apply_supersedes(findings: list[Finding], supersedes: dict[str, list[str]]) -> list[Finding]:
    """Drop findings of superseded rules that overlap a finding of the superseding rule."""
    if not supersedes:
        return findings
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    drop: set[int] = set()
    for group in by_file.values():
        for winner in group:
            losers = supersedes.get(winner.rule_id)
            if not losers:
                continue
            for other in group:
                if (
                    other.rule_id in losers
                    and other.line <= winner.end_line
                    and other.end_line >= winner.line
                ):
                    drop.add(id(other))
    return [f for f in findings if id(f) not in drop]


def sort_by_priority(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.priority, f.file, f.line, f.rule_id))


BENIGN_NOTE = (
    " (the argument is built only from constants and pure computations, so it is not"
    " attacker-controlled; confidence lowered)"
)


def weak_pattern_rules(
    supersedes: dict[str, list[str]], coverage: dict[str, set[str]]
) -> dict[str, set[str]]:
    """Pattern rule id -> languages in which a taint rule already judges the same call."""
    weak: dict[str, set[str]] = {}
    for winner, losers in supersedes.items():
        if winner in coverage:
            for loser in losers:
                weak.setdefault(loser, set()).update(coverage[winner])
    return weak


def demote_benign(
    findings: list[Finding], benign: Callable[[Finding], bool], weak: dict[str, set[str]]
) -> list[Finding]:
    """Lower "non-constant argument" heuristics whose argument is provably benign."""
    out: list[Finding] = []
    for f in findings:
        if f.rule_id in weak and f.confidence is not Confidence.LOW and benign(f):
            f = replace(f, confidence=f.confidence.lowered(1), message=f.message + BENIGN_NOTE)
        out.append(f)
    return out
