"""Command-line interface."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer

from vulnfab import __version__
from vulnfab.core.config import ConfigError
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.matcher import PatternError
from vulnfab.core.models import Confidence, Severity
from vulnfab.core.rules import RuleLoadError
from vulnfab.core.suppress import BaselineError
from vulnfab.plugins.registry import UnknownStackError
from vulnfab.reporters import console as console_reporter
from vulnfab.reporters import html_reporter, json_reporter, sarif
from vulnfab.scanners import osvupdate

app = typer.Typer(add_completion=False, help="Multi-stack SAST scanner.", no_args_is_help=True)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3


class OutputFormat(StrEnum):
    console = "console"
    json = "json"
    sarif = "sarif"
    html = "html"


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
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to file.")] = None,
    stack: Annotated[
        list[str] | None, typer.Option("--stack", help="Force a stack (repeatable).")
    ] = None,
    min_confidence: Annotated[
        Confidence | None, typer.Option("--min-confidence", help="Hide findings below this.")
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="Exit 1 if a finding is at least this.")
    ] = None,
    max_file_kb: Annotated[int | None, typer.Option("--max-file-kb", min=1)] = None,
    file_timeout: Annotated[float | None, typer.Option("--file-timeout", min=0.1)] = None,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Hide findings already in this baseline.")
    ] = None,
    write_baseline: Annotated[
        Path | None, typer.Option("--write-baseline", help="Write current findings as baseline.")
    ] = None,
    rules_path: Annotated[
        list[Path] | None, typer.Option("--rules", help="Extra rule files/directories.")
    ] = None,
    max_per_rule: Annotated[
        int, typer.Option("--max-per-rule", min=0, help="Console: rows per rule (0 = all).")
    ] = 10,
    schema_dump: Annotated[
        Path | None,
        typer.Option("--schema-dump", help="pg_dump --schema-only of the live database (drift)."),
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Do not read or write the result cache.")
    ] = False,
    jobs: Annotated[int, typer.Option("--jobs", "-j", min=1, help="Worker processes.")] = 1,
    history: Annotated[
        bool, typer.Option("--history", help="Also scan git history for committed secrets.")
    ] = False,
    history_limit: Annotated[
        int, typer.Option("--history-limit", min=1, help="Newest commits to scan with --history.")
    ] = 200,
    osv_db: Annotated[
        Path | None,
        typer.Option("--osv-db", help="Offline OSV advisories (dir/file) to check lockfiles."),
    ] = None,
    osv_scanner: Annotated[
        bool, typer.Option("--osv-scanner", help="Also run the optional osv-scanner binary.")
    ] = False,
    since: Annotated[
        str | None,
        typer.Option(
            "--since", help="Only report findings affected by changes since this git ref."
        ),
    ] = None,
) -> None:
    """Scan a repository."""
    if not path.is_dir():
        typer.echo(f"error: {path} is not a directory", err=True)
        raise typer.Exit(EXIT_USAGE)
    if schema_dump is not None and not schema_dump.is_file():
        typer.echo(f"error: schema dump {schema_dump} not found", err=True)
        raise typer.Exit(EXIT_USAGE)
    options = ScanOptions(
        stacks=stack,
        min_confidence=min_confidence,
        max_file_bytes=max_file_kb * 1024 if max_file_kb else None,
        file_timeout=file_timeout,
        baseline=baseline,
        write_baseline=write_baseline,
        extra_rule_paths=rules_path,
        schema_dump=schema_dump,
        use_cache=not no_cache,
        jobs=jobs,
        since=since,
        history=history,
        history_limit=history_limit,
        osv_db=osv_db,
        osv_scanner=osv_scanner,
    )
    try:
        result = scan(path, options)
    except (UnknownStackError, RuleLoadError, PatternError, ConfigError, BaselineError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    except Exception as exc:  # last-resort guard: never a raw traceback for users
        typer.echo(f"internal error: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(EXIT_INTERNAL) from exc

    if format is not OutputFormat.console:
        renderers = {
            OutputFormat.json: json_reporter.render,
            OutputFormat.sarif: sarif.render,
            OutputFormat.html: html_reporter.render,
        }
        text = renderers[format](result)
        if output:
            output.write_text(text)
        else:
            sys.stdout.write(text)
    elif output:
        with output.open("w") as handle:
            console_reporter.render(result, handle, max_per_rule)
    else:
        console_reporter.render(result, sys.stdout, max_per_rule)

    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)


rules_app = typer.Typer(help="Inspect and test rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


def _collect_rules(extra: list[Path] | None, stack: str | None) -> list[Any]:
    from vulnfab.core.rules import load_rules
    from vulnfab.plugins import registry

    packs: list[Path] = []
    for plugin in registry.discover():
        if stack is None or plugin.name == stack:
            packs.extend(p for p in plugin.rule_packs() if p.exists())
    packs.extend(extra or [])
    rules = load_rules(packs)
    return [r for r in rules if stack is None or r.stack == stack]


@rules_app.command("list")
def rules_list(
    stack: Annotated[str | None, typer.Option("--stack")] = None,
    rules_path: Annotated[list[Path] | None, typer.Option("--rules")] = None,
) -> None:
    """List loaded rules."""
    from vulnfab.core.rules import RuleLoadError

    try:
        rules = _collect_rules(rules_path, stack)
    except RuleLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    for r in sorted(rules, key=lambda r: r.id):
        state = "" if r.enabled else " (disabled)"
        typer.echo(f"{r.id:32} {r.kind:9} {r.severity.value:8} {r.confidence.value:6}{state}")
    typer.echo(f"{len(rules)} rule(s)")


@app.command("explain")
def explain(
    rule_id: Annotated[str, typer.Argument(help="Rule id, e.g. tpy-sqli.")],
    rules_path: Annotated[list[Path] | None, typer.Option("--rules")] = None,
) -> None:
    """Describe a rule: what it flags, why it matters, how to fix and suppress it."""
    from vulnfab.core.ruledocs import explain_text
    from vulnfab.core.rules import RuleLoadError

    try:
        rules = _collect_rules(rules_path, None)
    except RuleLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    match = next((r for r in rules if r.id == rule_id), None)
    if match is None:
        near = sorted(r.id for r in rules if rule_id.split("-")[-1] in r.id)[:5]
        hint = f" Did you mean: {', '.join(near)}?" if near else " Use `vulnfab rules list`."
        typer.echo(f"error: no rule with id {rule_id!r}.{hint}", err=True)
        raise typer.Exit(EXIT_USAGE)
    typer.echo(explain_text(match))


@rules_app.command("test")
def rules_test(
    rule: Annotated[str | None, typer.Option("--rule", help="Only this rule id.")] = None,
    stack: Annotated[str | None, typer.Option("--stack")] = None,
    tests_root: Annotated[Path, typer.Option("--tests-root")] = Path("tests/rules"),
    rules_path: Annotated[list[Path] | None, typer.Option("--rules")] = None,
) -> None:
    """Run each rule against its vulnerable and safe test files."""
    from vulnfab.core.rules import RuleLoadError
    from vulnfab.core.ruletest import run_rule_tests

    try:
        rules = _collect_rules(rules_path, stack)
    except RuleLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    if rule:
        rules = [r for r in rules if r.id == rule]
        if not rules:
            typer.echo(f"error: no rule with id {rule!r}", err=True)
            raise typer.Exit(EXIT_USAGE)
    failed = 0
    for r in sorted(rules, key=lambda r: r.id):
        res = run_rule_tests(r, tests_root)
        if res.ok:
            note = f" ({res.skipped})" if res.skipped else ""
            typer.echo(f"PASS {r.id}{note}")
        else:
            failed += 1
            typer.echo(f"FAIL {r.id}")
            for problem in res.problems:
                typer.echo(f"     {problem}")
    typer.echo(f"{len(rules) - failed}/{len(rules)} rules passed")
    if failed:
        raise typer.Exit(EXIT_FINDINGS)


@app.command("ir")
def ir_command(
    file: Annotated[Path, typer.Argument(help="Source file to lower into TIR (debugging aid).")],
) -> None:
    """Print the taint IR (TIR) of a Python, JS/TS or PHP file."""
    from vulnfab.core.loader import detect_language
    from vulnfab.core.lower import lower_file
    from vulnfab.core.models import SourceFile
    from vulnfab.core.parsing import ParseFailure, parse_file
    from vulnfab.core.tir import format_module

    if not file.is_file():
        typer.echo(f"error: {file} is not a file", err=True)
        raise typer.Exit(EXIT_USAGE)
    language = detect_language(file.name)
    if language is None:
        typer.echo(f"error: cannot tell the language of {file.name}", err=True)
        raise typer.Exit(EXIT_USAGE)
    text = file.read_text(encoding="utf-8", errors="replace")
    try:
        parsed = parse_file(SourceFile(file.name, language, text, "0" * 64))
        module = lower_file(parsed)
    except (ParseFailure, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.echo(format_module(module), nl=False)


osv_app = typer.Typer(help="Manage the offline OSV advisory database.", no_args_is_help=True)
app.add_typer(osv_app, name="osv")


@osv_app.command("update")
def osv_update(
    dest: Annotated[Path, typer.Argument(help="Directory to create or refresh.")],
    ecosystem: Annotated[
        list[str] | None,
        typer.Option("--ecosystem", "-e", help="npm, PyPI, Packagist (repeatable; default all)."),
    ] = None,
    base_url: Annotated[
        str, typer.Option("--base-url", help="Mirror of the OSV bucket.")
    ] = osvupdate.BASE_URL,
) -> None:
    """Download OSV advisories once (needs network); scans then use --osv-db DEST offline."""
    try:
        counts = osvupdate.update(dest, tuple(ecosystem or osvupdate.ECOSYSTEMS), base_url)
    except osvupdate.OsvUpdateError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    for eco, n in counts.items():
        typer.echo(f"{eco}: {n} advisories")
    typer.echo(f"scan with: vulnfab scan <path> --osv-db {dest}")


triage_app = typer.Typer(
    help="Record verdicts (true/false positive) for findings.", no_args_is_help=True
)
app.add_typer(triage_app, name="triage")

VerdictFile = Annotated[Path, typer.Option("--file", "-f", help="Verdict file (JSON).")]


@triage_app.command("set")
def triage_set(
    fingerprints: Annotated[list[str], typer.Argument(help="Finding fingerprint(s).")],
    verdict: Annotated[str, typer.Option("--verdict", "-v", help="tp | fp | dup")],
    file: VerdictFile = Path(".vulnfab-verdicts.json"),
    note: Annotated[str, typer.Option("--note", "-n")] = "",
    reviewer: Annotated[str, typer.Option("--reviewer")] = "",
) -> None:
    """Store a verdict for one or more fingerprints."""
    from vulnfab.core import triage

    try:
        count = triage.set_verdicts(file, fingerprints, verdict, note, reviewer)
    except triage.TriageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    typer.echo(f"{count} verdict(s) saved to {file}")


@triage_app.command("clear")
def triage_clear(
    fingerprints: Annotated[list[str], typer.Argument()],
    file: VerdictFile = Path(".vulnfab-verdicts.json"),
) -> None:
    """Remove verdicts."""
    from vulnfab.core import triage

    typer.echo(f"{triage.clear(file, fingerprints)} verdict(s) removed from {file}")


@triage_app.command("list")
def triage_list(
    findings: Annotated[Path, typer.Argument(help="JSON produced by `scan --format json`.")],
    file: VerdictFile = Path(".vulnfab-verdicts.json"),
) -> None:
    """List findings that still have no verdict."""
    from vulnfab.core import triage

    try:
        pending = triage.unreviewed(findings, file)
    except (OSError, ValueError, KeyError, triage.TriageError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    for f in pending:
        typer.echo(f"{f['fingerprint']}  {f['rule_id']}  {f['file']}:{f['line']}")
    typer.echo(f"{len(pending)} finding(s) without a verdict")
