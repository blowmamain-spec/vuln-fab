"""Rule test harness (WP-2.4): every rule is checked against vulnerable and safe files.

Layout: ``<tests_root>/<rule_id>/<file>``. A vulnerable file marks each line that must be
reported with a trailing comment ``# vuln: <rule_id>`` (or ``// vuln:``, ``-- vuln:``).
The reported set must equal the annotated set exactly. A safe file must yield no finding
for that rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from vulnfab.core.loader import detect_language
from vulnfab.core.matcher import PatternError, compile_rule
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import ParseFailure, parse_file
from vulnfab.core.ruleengine import findings_for_file
from vulnfab.core.rules import PatternRule

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


def run_rule_tests(rule: object, tests_root: Path) -> RuleTestResult:
    rule_id = getattr(rule, "id", "?")
    result = RuleTestResult(rule_id)
    base = tests_root / rule_id
    declared = list(getattr(rule.tests, "vulnerable", [])) + list(getattr(rule.tests, "safe", []))  # type: ignore[attr-defined]
    for name in declared:
        if not (base / name).is_file():
            result.problems.append(f"missing test file {base / name}")
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
