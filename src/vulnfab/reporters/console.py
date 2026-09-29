from __future__ import annotations

from typing import TextIO

from rich.console import Console
from rich.table import Table

from vulnfab.core.report import ScanResult

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render(result: ScanResult, stream: TextIO, max_per_rule: int = 10) -> None:
    console = Console(file=stream, highlight=False, width=max(Console().width, 100))
    findings = sorted(result.findings, key=lambda f: (-f.priority, f.file, f.line))
    total = len(findings)
    hidden_by_cap: dict[str, int] = {}
    if max_per_rule > 0:
        shown: list = []  # type: ignore[type-arg]
        seen: dict[str, int] = {}
        for f in findings:
            seen[f.rule_id] = seen.get(f.rule_id, 0) + 1
            if seen[f.rule_id] <= max_per_rule:
                shown.append(f)
            else:
                hidden_by_cap[f.rule_id] = hidden_by_cap.get(f.rule_id, 0) + 1
        findings = shown
    if findings:
        table = Table(show_lines=False)
        for column in ("Severity", "Conf.", "Rule", "Location", "Title"):
            table.add_column(column, overflow="fold")
        for f in findings:
            style = _SEVERITY_STYLE[f.severity.value]
            table.add_row(
                f"[{style}]{f.severity.value}[/]",
                f.confidence.value,
                f.rule_id,
                f"{f.file}:{f.line}",
                f.title,
            )
        console.print(table)
    else:
        console.print("No findings.")
    for rule_id, count in sorted(hidden_by_cap.items()):
        console.print(
            f"[dim]… {count} more {rule_id} finding(s) not shown "
            "(--max-per-rule 0 shows all, --format json has everything)[/]"
        )
    cov = result.coverage
    console.print(
        f"\nStacks: {', '.join(result.stacks) or '-'} · "
        f"files scanned: {cov.files_scanned} · findings: {total}"
    )
    console.print("[bold]Coverage & limitations[/]")
    if cov.files_skipped:
        console.print(f"  skipped files: {len(cov.files_skipped)}")
        for s in cov.files_skipped[:10]:
            console.print(f"    {s.file} ({s.reason}{': ' + s.detail if s.detail else ''})")
    if cov.syntax_errors:
        console.print(f"  files with syntax errors (partially analysed): {len(cov.syntax_errors)}")
    if cov.unresolved:
        console.print(f"  unresolved constructs: {len(cov.unresolved)}")
        for u in cov.unresolved[:8]:
            console.print(f"    {u.file}:{u.line} ({u.kind}) {u.detail}")
        if len(cov.unresolved) > 8:
            console.print(f"    … and {len(cov.unresolved) - 8} more (see --format json)")
    if cov.hidden_low_confidence:
        console.print(
            f"  {cov.hidden_low_confidence} finding(s) hidden below the confidence threshold"
        )
    for a in cov.assumptions:
        console.print(f"  assumption: {a}")
    for adapter in cov.adapters:
        console.print(f"  adapter {adapter.name}: {adapter.status}")
