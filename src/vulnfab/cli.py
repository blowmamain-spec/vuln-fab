"""Command-line interface."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from vulnfab import __version__
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence, Severity
from vulnfab.plugins.registry import UnknownStackError
from vulnfab.reporters import console as console_reporter
from vulnfab.reporters import json_reporter

app = typer.Typer(add_completion=False, help="Multi-stack SAST scanner.", no_args_is_help=True)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3


class OutputFormat(StrEnum):
    console = "console"
    json = "json"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vulnfab {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """vulnfab command group."""


@app.command("scan")
def scan_command(
    path: Annotated[Path, typer.Argument(help="Repository directory to scan.")],
    format: Annotated[OutputFormat, typer.Option("--format", help="Output format.")] = (
        OutputFormat.console
    ),
    output: Annotated[Path | None, typer.Option("--output", help="Write to file.")] = None,
    stack: Annotated[
        list[str] | None, typer.Option("--stack", help="Force a stack (repeatable).")
    ] = None,
    min_confidence: Annotated[
        Confidence, typer.Option("--min-confidence", help="Hide findings below this.")
    ] = Confidence.MEDIUM,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="Exit 1 if a finding is at least this.")
    ] = None,
    max_file_kb: Annotated[int, typer.Option("--max-file-kb", min=1)] = 1024,
    file_timeout: Annotated[float, typer.Option("--file-timeout", min=0.1)] = 10.0,
) -> None:
    """Scan a repository."""
    if not path.is_dir():
        typer.echo(f"error: {path} is not a directory", err=True)
        raise typer.Exit(EXIT_USAGE)
    options = ScanOptions(
        stacks=stack,
        min_confidence=min_confidence,
        max_file_bytes=max_file_kb * 1024,
        file_timeout=file_timeout,
    )
    try:
        result = scan(path, options)
    except UnknownStackError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except Exception as exc:  # last-resort guard: never a raw traceback for users
        typer.echo(f"internal error: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(EXIT_INTERNAL) from exc

    if format is OutputFormat.json:
        text = json_reporter.render(result)
        if output:
            output.write_text(text)
        else:
            sys.stdout.write(text)
    elif output:
        with output.open("w") as handle:
            console_reporter.render(result, handle)
    else:
        console_reporter.render(result, sys.stdout)

    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)
