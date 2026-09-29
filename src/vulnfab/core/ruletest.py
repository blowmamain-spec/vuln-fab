"""Rule test harness (WP-2.4): every rule is checked against vulnerable and safe files.

Layout: ``<tests_root>/<rule_id>/<file>``. A vulnerable file marks each line that must be
reported with a trailing comment ``# vuln: <rule_id>`` (or ``// vuln:``, ``-- vuln:``).
The reported set must equal the annotated set exactly. A safe file must yield no finding
for that rule.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from vulnfab.core.loader import Repo, detect_language
from vulnfab.core.matcher import PatternError, compile_rule
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import ParseFailure, parse_file
from vulnfab.core.ruleengine import findings_for_file
from vulnfab.core.rules import CrosscheckRule, PatternRule, ScannerRule, SchemaRule, TaintRule
from vulnfab.core.schemarules import CheckError, run_schema_rules

ANNOTATION_RE = re.compile(r"(?:#|//|--)\s*vuln:\s*([a-z][a-z0-9-]*)")


@dataclass
class RuleTestResult:
    rule_id: str
    problems: list[str] = field(default_factory=list)
    skipped: str | None = None

    @property
    def ok(self) -> bool:
        return not self.problems


def annotated_lines(text: str, rule_id: str) -> set[int]:
    lines: set[int] = set()
    for number, line in enumerate(text.split("\n"), start=1):
        for m in ANNOTATION_RE.finditer(line):
            if m.group(1) == rule_id:
                lines.add(number)
    return lines


def _reported_lines(rule: PatternRule, crule, path: Path) -> tuple[set[int], str | None]:  # type: ignore[no-untyped-def]
    language = detect_language(path.name)
    if language is None or language not in rule.languages:
        return (
            set(),
            f"{path.name}: language {language!r} is not in rule languages {rule.languages}",
        )
    text = path.read_text(encoding="utf-8")
    sf = SourceFile(path.name, language, text, "0" * 64)
    try:
        pf = parse_file(sf)
    except ParseFailure as exc:
        return set(), f"{path.name}: cannot parse ({exc})"
    lines = {f.line for f, _ in findings_for_file([crule], pf) if f.rule_id == rule.id}
    return lines, None


def _schema_lines(rule: SchemaRule, path: Path) -> tuple[set[int], str | None]:
    from vulnfab.plugins import registry

    plugin = next((p for p in registry.discover() if p.name == rule.stack), None)
    layout = getattr(plugin, "fixture_path", None)
    if plugin is None or layout is None:
        return set(), f"stack {rule.stack!r} provides no test fixture layout"
    dest = layout(path.name)
    if dest is None:
        return set(), f"{path.name}: cannot place this file in a {rule.stack} fixture repository"
    with tempfile.TemporaryDirectory() as tmp:
        extra = path.parent / "_repo"  # extra files the schema needs (e.g. migrations)
        if extra.is_dir():
            for f in extra.rglob("*"):
                if f.is_file():
                    copy = Path(tmp) / f.relative_to(extra)
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    copy.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        target = Path(tmp) / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        repo = Repo(Path(tmp))
        model = plugin.extract_schema(repo)
        if model is None:
            return set(), f"{path.name}: plugin found no project in the fixture"
        dump = path.with_suffix(".dump.sql")
        attach = getattr(plugin, "attach_drift", None)
        if dump.is_file() and attach is not None:
            attach(model, dump.name, dump.read_text(encoding="utf-8"))
        try:
            hits = run_schema_rules([rule], model, repo)
        except CheckError as exc:
            return set(), str(exc)
    return {f.line for f, _ in hits if f.file == dest}, None


def run_rule_tests(rule: object, tests_root: Path) -> RuleTestResult:
    rule_id = getattr(rule, "id", "?")
    result = RuleTestResult(rule_id)
    base = tests_root / rule_id
    declared = list(getattr(rule.tests, "vulnerable", [])) + list(getattr(rule.tests, "safe", []))  # type: ignore[attr-defined]
    for name in declared:
        if not (base / name).is_file():
            result.problems.append(f"missing test file {base / name}")
    if isinstance(rule, SchemaRule):
        _check_lines(result, rule, base, lambda path: _schema_lines(rule, path))
        return result
    if isinstance(rule, (ScannerRule, CrosscheckRule)):
        _check_lines(result, rule, base, lambda path: _engine_lines(rule, base, path))
        return result
    if isinstance(rule, TaintRule):
        _check_lines(result, rule, base, lambda path: _taint_lines(rule, path))
        return result
    if not isinstance(rule, PatternRule):
        result.skipped = f"kind {getattr(rule, 'kind', '?')!r}: only file presence is checked here"
        return result
    try:
        crule = compile_rule(rule)
    except PatternError as exc:
        result.problems.append(str(exc))
        return result

    for name in rule.tests.vulnerable:
        path = base / name
        if not path.is_file():
            continue
        expected = annotated_lines(path.read_text(encoding="utf-8"), rule.id)
        if not expected:
            result.problems.append(f"{name}: vulnerable file has no '# vuln: {rule.id}' annotation")
            continue
        got, err = _reported_lines(rule, crule, path)
        if err:
            result.problems.append(err)
            continue
        missed, extra = sorted(expected - got), sorted(got - expected)
        if missed:
            result.problems.append(f"{name}: expected finding not reported at line(s) {missed}")
        if extra:
            result.problems.append(f"{name}: unexpected finding at line(s) {extra}")
    for name in rule.tests.safe:
        path = base / name
        if not path.is_file():
            continue
        got, err = _reported_lines(rule, crule, path)
        if err:
            result.problems.append(err)
        elif got:
            result.problems.append(
                f"{name}: safe file produced finding(s) at line(s) {sorted(got)}"
            )
    return result


def _taint_lines(rule: TaintRule, path: Path) -> tuple[set[int], str | None]:
    from vulnfab.core.taintrules import taint_findings_for_file

    language = detect_language(path.name)
    if language is None or language not in rule.languages:
        return set(), f"{path.name}: language {language!r} is not in rule languages"
    sf = SourceFile(path.name, language, path.read_text(encoding="utf-8"), "0" * 64)
    try:
        pf = parse_file(sf)
    except ParseFailure as exc:
        return set(), f"{path.name}: cannot parse ({exc})"
    return {f.line for f, _ in taint_findings_for_file([rule], pf)}, None


def _engine_lines(
    rule: ScannerRule | CrosscheckRule, base: Path, path: Path
) -> tuple[set[int], str | None]:
    """Run the whole engine on a throw-away repository holding the test file.

    ``schema.sql`` next to the test files (if present) becomes the Supabase migration, so
    cross-check rules see a database schema.
    """
    from vulnfab.core.engine import ScanOptions, scan
    from vulnfab.core.models import Confidence

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        extra = base / "_repo"  # extra files that make the stack plugin activate
        if extra.is_dir():
            for f in extra.rglob("*"):
                if f.is_file():
                    dest_file = root / f.relative_to(extra)
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    dest_file.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        schema = base / "schema.sql"
        if schema.is_file():
            migration = root / "supabase" / "migrations" / "20240101000000_schema.sql"
            migration.parent.mkdir(parents=True)
            migration.write_text(schema.read_text(encoding="utf-8"), encoding="utf-8")
        rel = path.name if path.name.startswith(".env") else f"src/{path.name}"
        from vulnfab.plugins import registry

        plugin = next((p for p in registry.discover() if p.name == rule.stack), None)
        placed = getattr(plugin, "fixture_path", lambda _name: None)(path.name)
        if placed is not None and not path.name.startswith(".env"):
            rel = placed
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        result = scan(root, ScanOptions(min_confidence=Confidence.LOW))
    return {f.line for f in result.findings if f.rule_id == rule.id and f.file == rel}, None


def _check_lines(result: RuleTestResult, rule, base: Path, run) -> None:  # type: ignore[no-untyped-def]
    for name in rule.tests.vulnerable:
        path = base / name
        if not path.is_file():
            continue
        expected = annotated_lines(path.read_text(encoding="utf-8"), rule.id)
        if not expected:
            result.problems.append(f"{name}: vulnerable file has no 'vuln: {rule.id}' annotation")
            continue
        got, err = run(path)
        if err:
            result.problems.append(err)
            continue
        missed, extra = sorted(expected - got), sorted(got - expected)
        if missed:
            result.problems.append(f"{name}: expected finding not reported at line(s) {missed}")
        if extra:
            result.problems.append(f"{name}: unexpected finding at line(s) {extra}")
    for name in rule.tests.safe:
        path = base / name
        if not path.is_file():
            continue
        got, err = run(path)
        if err:
            result.problems.append(err)
        elif got:
            result.problems.append(
                f"{name}: safe file produced finding(s) at line(s) {sorted(got)}"
            )
