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


def render(result: ScanResult, stream: TextIO) -> None:
    console = Console(file=stream, highlight=False, width=max(Console().width, 100))
    findings = sorted(result.findings, key=lambda f: (-f.priority, f.file, f.line))
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
    cov = result.coverage
    console.print(
        f"\nStacks: {', '.join(result.stacks) or '-'} · "
        f"files scanned: {cov.files_scanned} · findings: {len(findings)}"
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
    if cov.hidden_low_confidence:
        console.print(
            f"  {cov.hidden_low_confidence} finding(s) hidden below the confidence threshold"
        )
    for a in cov.assumptions:
        console.print(f"  assumption: {a}")
    for adapter in cov.adapters:
        console.print(f"  adapter {adapter.name}: {adapter.status}")
