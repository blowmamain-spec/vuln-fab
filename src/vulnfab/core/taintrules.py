"""Run taint rules over parsed files: lower to TIR, analyse across the project, emit findings."""

from __future__ import annotations

from collections.abc import Iterable

from vulnfab.core.lower import lower_file
from vulnfab.core.models import Finding, ParsedFile, Unresolved
from vulnfab.core.rules import TaintRule
from vulnfab.core.taint import FactCache, ProjectAnalysis
from vulnfab.core.taintspec import TaintSpec
from vulnfab.core.tir import ModuleIR

SNIPPET_LIMIT = 300


def spec_for(rule: TaintRule) -> TaintSpec:
    return TaintSpec.from_rule(
        rule.sources,
        rule.sinks,
        rule.sanitizers,
        rule.propagators,
        rule.guards,
        rule.validators,
    )


def taint_findings(
    rules: list[TaintRule],
    files: Iterable[ParsedFile],
    notes: list[Unresolved] | None = None,
) -> list[tuple[Finding, str]]:
    """Return ``(finding-without-fingerprint, enclosing-symbol)`` for a set of parsed files."""
    active = [r for r in rules if r.enabled]
    parsed = [pf for pf in files if not pf.has_syntax_errors]
    out: list[tuple[Finding, str]] = []
    if not active or not parsed:
        return out
    lines = {pf.path: pf.source.decode("utf-8", errors="replace").split("\n") for pf in parsed}
    lowered: dict[str, ModuleIR] = {}
    for pf in parsed:
        if any(pf.language in r.languages for r in active):
            lowered[pf.path] = lower_file(pf)
    facts: FactCache = {}
    for rule in active:
        modules = [m for m in lowered.values() if m.language in rule.languages]
        analysis = ProjectAnalysis(modules, spec_for(rule), facts=facts)
        hits = analysis.run()
        if notes is not None:
            notes.extend(
                Unresolved(
                    "taint_truncated",
                    file,
                    line,
                    f"{rule.id}: analysis of {function} hit its work limit; "
                    "flows through it are missed",
                )
                for file, function, line in analysis.truncated
            )
        for hit in hits:
            file_lines = lines.get(hit.file, [])
            text = file_lines[hit.line - 1].strip() if 0 < hit.line <= len(file_lines) else ""
            out.append(
                (
                    Finding(
                        rule_id=rule.id,
                        title=rule.display_title,
                        cwe=tuple(rule.cwe),
                        owasp=rule.owasp,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        tier=rule.tier,
                        file=hit.file,
                        line=hit.line,
                        end_line=hit.line,
                        snippet=text[:SNIPPET_LIMIT],
                        trace=hit.trace,
                        unresolved_hops=hit.hops,
                        fix=rule.fix,
                        message=rule.message,
                    ),
                    hit.function,
                )
            )
    return out


def taint_findings_for_file(rules: list[TaintRule], pf: ParsedFile) -> list[tuple[Finding, str]]:
    return taint_findings(rules, [pf])
