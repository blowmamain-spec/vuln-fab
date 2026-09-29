"""Scoring, deduplication and supersession (docs/spec.md section 4)."""

from __future__ import annotations

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
