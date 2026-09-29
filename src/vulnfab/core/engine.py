"""Scan orchestration: load -> detect -> parse -> rules -> suppress -> score -> result."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from vulnfab.core import scoring
from vulnfab.core.config import ScanConfig, load_config
from vulnfab.core.fingerprint import FingerprintAllocator
from vulnfab.core.loader import DEFAULT_MAX_FILE_BYTES, Repo
from vulnfab.core.matcher import CompiledRule
from vulnfab.core.models import (
    Confidence,
    DataAccess,
    Finding,
    ParsedUnit,
    SchemaModel,
    SkippedFile,
)
from vulnfab.core.parsing import Deadline, TimeoutExceeded, clear_parse_cache
from vulnfab.core.report import Coverage, ScanResult
from vulnfab.core.ruleengine import compile_pattern_rules, findings_for_file
from vulnfab.core.rules import (
    CrosscheckRule,
    RuleError,
    RuleLoadError,
    ScannerRule,
    SchemaRule,
    TaintRule,
    load_rules,
)
from vulnfab.core.scannerrules import ScannerError, run_scanner_rules
from vulnfab.core.schemarules import CheckError, run_crosscheck_rules, run_schema_rules
from vulnfab.core.suppress import PerFileIgnores, is_nosec, load_baseline, write_baseline
from vulnfab.core.taintrules import taint_findings_for_file
from vulnfab.plugins import registry

DEFAULT_FILE_TIMEOUT = 10.0


@dataclass
class ScanOptions:
    stacks: list[str] | None = None
    min_confidence: Confidence | None = None  # None: use config, then MEDIUM
    max_file_bytes: int | None = None  # None: use config, then default
    file_timeout: float | None = None
    baseline: Path | None = None
    write_baseline: Path | None = None
    extra_rule_paths: list[Path] | None = None
    schema_dump: Path | None = None


def _load_plugin_rules(selected: list[registry.Selected], extra: list[Path] | None) -> list[object]:
    rules: list[object] = []
    mismatches: list[RuleError] = []
    for sel in selected:
        packs = [p for p in sel.plugin.rule_packs() if p.exists()]
        for rule in load_rules(packs):
            if rule.stack != sel.plugin.name:
                mismatches.append(
                    RuleError(
                        str(packs),
                        1,
                        rule.id,
                        f"rule stack {rule.stack!r} does not match plugin {sel.plugin.name!r}",
                    )
                )
            else:
                rules.append(rule)
    if extra:
        rules.extend(load_rules(extra))
    if mismatches:
        raise RuleLoadError(mismatches)
    return rules


def scan(path: Path, options: ScanOptions | None = None) -> ScanResult:
    clear_parse_cache()
    try:
        return _scan(path, options or ScanOptions())
    finally:
        clear_parse_cache()


def _scan(path: Path, options: ScanOptions) -> ScanResult:
    config: ScanConfig = load_config(path)
    min_confidence = options.min_confidence or config.min_confidence or Confidence.MEDIUM
    max_file_bytes = options.max_file_bytes or (
        config.max_file_kb * 1024 if config.max_file_kb else DEFAULT_MAX_FILE_BYTES
    )
    file_timeout = options.file_timeout or config.file_timeout or DEFAULT_FILE_TIMEOUT

    repo = Repo(path, max_file_bytes=max_file_bytes, extra_ignore=config.exclude)
    selected = registry.select(registry.discover(), repo, options.stacks)
    rules = [
        r
        for r in _load_plugin_rules(selected, options.extra_rule_paths)
        if getattr(r, "id", "") not in set(config.disable_rules)
    ]
    crules: list[CompiledRule] = compile_pattern_rules(rules)
    schema_rules = [r for r in rules if isinstance(r, SchemaRule)]
    scanner_rules = [r for r in rules if isinstance(r, ScannerRule)]
    crosscheck_rules = [r for r in rules if isinstance(r, CrosscheckRule)]
    taint_rules = [r for r in rules if isinstance(r, TaintRule)]
    supersedes = {r.id: list(r.supersedes) for r in rules if getattr(r, "supersedes", None)}  # type: ignore[attr-defined]

    loaded = repo.load()
    texts = {f.path: f.text for f in loaded.files}
    coverage = Coverage(
        files_skipped=list(loaded.skipped),
        files_ignored=loaded.ignored_count,
        files_unsupported=loaded.unsupported_count,
    )
    scanned: set[str] = set()
    raw: list[tuple[Finding, str]] = []
    facts: list[DataAccess] = []
    schemas: dict[str, SchemaModel] = {}

    for sel in selected:
        plugin = sel.plugin
        plugin_rules = [c for c in crules if c.rule.stack == plugin.name]
        plugin_taint = [r for r in taint_rules if r.stack == plugin.name]
        unit: ParsedUnit = plugin.parse([f for f in loaded.files if f.language in plugin.languages])
        facts.extend(plugin.data_access(unit))
        coverage.files_skipped.extend(unit.skipped)
        coverage.unresolved.extend(unit.unresolved)
        schema = plugin.extract_schema(repo)
        if schema is not None:
            schemas[plugin.name] = schema
        if schema is not None and options.schema_dump is not None:
            attach = getattr(plugin, "attach_drift", None)
            if attach is not None:
                attach(
                    schema,
                    options.schema_dump.name,
                    options.schema_dump.read_text(encoding="utf-8"),
                )
        if schema is not None:
            coverage.unresolved.extend(schema.unresolved)
            coverage.assumptions.extend(
                a for a in schema.assumptions if a not in coverage.assumptions
            )
            mine = [r for r in schema_rules if r.stack == plugin.name]
            try:
                raw.extend(run_schema_rules(mine, schema, repo))
            except CheckError as exc:
                raise RuleLoadError([RuleError(plugin.name, 1, None, str(exc))]) from exc
        for pf in unit.files.values():
            scanned.add(pf.path)
            if pf.has_syntax_errors:
                coverage.syntax_errors.append(pf.path)
            try:
                raw.extend(findings_for_file(plugin_rules, pf, Deadline(file_timeout)))
                if plugin_taint and not pf.has_syntax_errors:
                    raw.extend(taint_findings_for_file(plugin_taint, pf))
            except TimeoutExceeded:
                coverage.files_skipped.append(
                    SkippedFile(pf.path, "timeout", f"exceeded {file_timeout:g}s")
                )

    active = {s.plugin.name for s in selected}
    loose_sql = sorted(f.path for f in loaded.files if f.language == "sql")
    if loose_sql and "supabase" not in active:
        coverage.assumptions.append(
            f"{len(loose_sql)} .sql file(s) were NOT analysed: no Supabase project layout "
            "(supabase/migrations/*.sql) was found. Put your SQL files in "
            "<project>/supabase/migrations/ (file names must sort in the order they should run)."
        )
    try:
        raw.extend(run_scanner_rules([r for r in scanner_rules if r.stack in active], loaded.files))
        cross = [r for r in crosscheck_rules if r.stack in active]
        model = schemas.get("supabase") or next(iter(schemas.values()), None)
        if cross and model is None:
            coverage.assumptions.append(
                "Cross-check rules were skipped: no database schema was found to compare with."
            )
        elif cross and model is not None:
            raw.extend(run_crosscheck_rules(cross, facts, model, repo))
    except (CheckError, ScannerError) as exc:
        raise RuleLoadError([RuleError("engine", 1, None, str(exc))]) from exc

    coverage.files_scanned = len(scanned)
    coverage.syntax_errors = sorted(set(coverage.syntax_errors))
    coverage.files_skipped.sort(key=lambda s: (s.file, s.reason))

    allocator = FingerprintAllocator()
    findings: list[Finding] = []
    for finding, symbol in sorted(raw, key=lambda i: (i[0].file, i[0].line, i[0].rule_id)):
        fingerprint = allocator.allocate(finding.rule_id, finding.file, finding.snippet, symbol)
        findings.append(replace(finding, fingerprint=fingerprint))
    findings = scoring.dedupe(findings)
    findings = scoring.apply_supersedes(findings, supersedes)

    # config: per-file ignores and severity overrides
    ignores = PerFileIgnores(config.per_file_ignores)
    kept: list[Finding] = []
    for f in findings:
        if ignores.ignores(f.file, f.rule_id):
            coverage.suppressed_config += 1
            continue
        override = config.severity_overrides.get(f.rule_id)
        kept.append(replace(f, severity=override) if override else f)
    findings = [scoring.adjust(f) for f in kept]

    # inline nosec
    kept = []
    line_cache: dict[str, list[str]] = {}
    for f in findings:
        lines = line_cache.setdefault(f.file, texts.get(f.file, "").split("\n"))
        if is_nosec(f, lines):
            coverage.suppressed_nosec += 1
        else:
            kept.append(f)
    findings = kept

    if options.write_baseline:
        write_baseline(options.write_baseline, findings)
    if options.baseline:
        known = load_baseline(options.baseline)
        fresh = [f for f in findings if f.fingerprint not in known]
        coverage.suppressed_baseline = len(findings) - len(fresh)
        findings = fresh

    visible = [f for f in findings if f.confidence.rank >= min_confidence.rank]
    coverage.hidden_low_confidence = len(findings) - len(visible)
    return ScanResult(
        target=str(path),
        stacks=[s.plugin.name for s in selected],
        findings=visible,
        coverage=coverage,
    )
