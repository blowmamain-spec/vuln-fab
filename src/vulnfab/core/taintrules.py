"""Run taint rules over parsed files: lower to TIR, analyse each function, emit findings."""

from __future__ import annotations

from vulnfab.core.lower import lower_file
from vulnfab.core.models import Finding, ParsedFile
from vulnfab.core.rules import TaintRule
from vulnfab.core.taint import analyze_function
from vulnfab.core.taintspec import TaintSpec

SNIPPET_LIMIT = 300


def spec_for(rule: TaintRule) -> TaintSpec:
    return TaintSpec.from_rule(rule.sources, rule.sinks, rule.sanitizers, rule.propagators)


def taint_findings_for_file(rules: list[TaintRule], pf: ParsedFile) -> list[tuple[Finding, str]]:
    """Return ``(finding-without-fingerprint, enclosing-symbol)`` for one parsed file."""
    applicable = [r for r in rules if r.enabled and pf.language in r.languages]
    if not applicable:
        return []
    module = lower_file(pf)
    lines = pf.source.decode("utf-8", errors="replace").split("\n")
    out: list[tuple[Finding, str]] = []
    for rule in applicable:
        spec = spec_for(rule)
        for fn in module.functions:
            for hit in analyze_function(fn, spec, pf.path):
                text = lines[hit.line - 1].strip() if 0 < hit.line <= len(lines) else ""
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
                            file=pf.path,
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
