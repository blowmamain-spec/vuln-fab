"""Run compiled pattern rules against parsed files and produce findings."""

from __future__ import annotations

from vulnfab.core.matcher import CompiledRule, FileIndex, compile_rule, run_rule
from vulnfab.core.models import Finding, ParsedFile
from vulnfab.core.parsing import Deadline, enclosing_symbol, node_text
from vulnfab.core.rules import PatternRule

SNIPPET_LIMIT = 300


def compile_pattern_rules(rules: list[object]) -> list[CompiledRule]:
    return [compile_rule(r) for r in rules if isinstance(r, PatternRule) and r.enabled]


def _snippet(text: str) -> str:
    return text if len(text) <= SNIPPET_LIMIT else text[:SNIPPET_LIMIT] + "..."


def findings_for_file(
    crules: list[CompiledRule], pf: ParsedFile, deadline: Deadline | None = None
) -> list[tuple[Finding, str]]:
    """Return ``(finding-without-fingerprint, enclosing-symbol)`` for one parsed file."""
    applicable = [c for c in crules if pf.language in c.rule.languages]
    if not applicable:
        return []
    index = FileIndex(pf.tree, deadline)
    out: list[tuple[Finding, str]] = []
    for crule in applicable:
        rule = crule.rule
        for m in run_rule(crule, pf.language, index):
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
                        line=m.node.start_point.row + 1,
                        end_line=m.node.end_point.row + 1,
                        snippet=_snippet(node_text(m.node, pf.source)),
                        fix=rule.fix,
                    ),
                    enclosing_symbol(m.node, pf.source),
                )
            )
    return out
