"""Temporary hard-coded rule used to exercise the pipeline end to end (WP-1.5).

Replaced by the YAML ``py-eval`` rule in WP-2.6; keep the rule id identical so snapshots hold.
"""

from __future__ import annotations

from vulnfab.core.models import Confidence, Finding, ParsedUnit, Severity
from vulnfab.core.parsing import Deadline, enclosing_symbol, node_text, walk

RULE_ID = "py-eval"


def run(unit: ParsedUnit, deadline_seconds: float | None = None) -> list[tuple[Finding, str]]:
    """Return ``(finding-without-fingerprint, enclosing-symbol)`` pairs."""
    out: list[tuple[Finding, str]] = []
    for pf in unit.files.values():
        if pf.language != "python":
            continue
        deadline = Deadline(deadline_seconds)
        for node in walk(pf.tree.root_node, deadline):
            if node.type != "call":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "identifier" or node_text(fn, pf.source) != "eval":
                continue
            text = node_text(node, pf.source)
            out.append(
                (
                    Finding(
                        rule_id=RULE_ID,
                        title="Use of eval()",
                        cwe=("CWE-95",),
                        owasp="A03:2021",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        tier=None,
                        file=pf.path,
                        line=node.start_point.row + 1,
                        end_line=node.end_point.row + 1,
                        snippet=text,
                        fix="Avoid eval(); use ast.literal_eval or an explicit parser.",
                    ),
                    enclosing_symbol(node, pf.source),
                )
            )
    return out
