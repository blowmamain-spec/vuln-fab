from pathlib import Path

import pytest

from vulnfab.core.models import Confidence, Severity
from vulnfab.core.rules import (
    PatternRule,
    RuleLoadError,
    SchemaRule,
    TaintRule,
    load_rules,
    parse_rules,
)

GOOD = """
id: dj-raw-sql-interp
languages: [python]
stack: django
severity: high
confidence: medium
cwe: [CWE-89]
message: "Raw SQL dengan interpolasi. Gunakan parameter."
pattern: "$M.objects.raw($Q)"
where:
  - {metavariable: Q, kind: fstring_or_concat}
fix: "Model.objects.raw('... WHERE id = %s', [value])"
tests:
  vulnerable: [vuln.py]
  safe: [safe.py]
"""


def _errors(text: str) -> list[str]:
    _, errs = parse_rules(text, "r.yml")
    return [str(e) for e in errs]


def test_valid_pattern_rule() -> None:
    rules, errs = parse_rules(GOOD, "r.yml")
    assert errs == []
    rule = rules[0]
    assert isinstance(rule, PatternRule)
    assert rule.severity is Severity.HIGH and rule.confidence is Confidence.MEDIUM
    assert rule.anchors == ["$M.objects.raw($Q)"]
    assert rule.where[0].metavariable == "Q"
    assert rule.display_title == "Raw SQL dengan interpolasi"


def test_rules_list_and_kinds() -> None:
    text = """
rules:
  - id: lv-sqli-dbraw
    stack: laravel
    kind: taint
    languages: [php]
    severity: high
    confidence: medium
    message: m
    sources: ['call request->input']
    sinks: ['call DB::raw arg0']
    tests: {vulnerable: [a.php], safe: [b.php]}
  - id: sb-rls-missing
    stack: supabase
    kind: schema
    severity: critical
    confidence: high
    message: m
    condition: "table.schema == 'public' and not table.rls_enabled"
    tests: {vulnerable: [a.sql], safe: [b.sql]}
"""
    rules, errs = parse_rules(text, "r.yml")
    assert errs == []
    assert isinstance(rules[0], TaintRule) and isinstance(rules[1], SchemaRule)


def test_error_reports_file_line_rule_and_field() -> None:
    bad = GOOD.replace("severity: high", "severity: urgent")
    (msg,) = _errors(bad)
    assert msg.startswith("r.yml:2: rule 'dj-raw-sql-interp':")
    assert "severity" in msg


def test_error_line_for_second_rule_in_list() -> None:
    text = "rules:\n  - " + GOOD.strip().replace("\n", "\n    ") + "\n  - id: BAD\n"
    errs = _errors(text)
    assert any(e.startswith("r.yml:") and "'BAD'" in e for e in errs)


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        (lambda t: t.replace("id: dj-raw-sql-interp", "id: BadId"), "id must look like"),
        (lambda t: t.replace("cwe: [CWE-89]", "cwe: [89]"), "bad CWE"),
        (lambda t: t.replace("languages: [python]", "languages: [cobol]"), "unknown language"),
        (lambda t: t.replace("languages: [python]", "languages: []"), "must not be empty"),
        (
            lambda t: t.replace("safe: [safe.py]", "safe: []"),
            "at least one vulnerable and one safe",
        ),
        (lambda t: t.replace("pattern:", "patern:"), "unknown field"),
        (lambda t: t.replace('pattern: "$M.objects.raw($Q)"\n', ""), "exactly one of 'pattern'"),
        (lambda t: t + "kind: nonsense\n", "kind"),
        (lambda t: t.replace("kind: fstring_or_concat", "kind: regex"), "requires 'regex'"),
        (
            lambda t: t.replace("kind: fstring_or_concat}", "kind: fstring_or_concat, regex: x}"),
            "only valid with kind regex",
        ),
        (lambda t: t.replace("message:", "msg:"), "field is required"),
    ],
)
def test_invalid_rules_are_rejected(mutation, needle) -> None:  # type: ignore[no-untyped-def]
    errs = _errors(mutation(GOOD))
    assert errs, "expected at least one error"
    assert needle in "\n".join(errs)


def test_schema_condition_must_be_safe() -> None:
    text = """
id: sb-evil
stack: supabase
kind: schema
severity: high
confidence: high
message: m
condition: "__import__('os').system('id')"
tests: {vulnerable: [a.sql], safe: [b.sql]}
"""
    (msg,) = _errors(text)
    assert "unsafe or invalid condition" in msg


def test_schema_needs_exactly_one_of_check_or_condition() -> None:
    base = """
id: sb-x
stack: supabase
kind: schema
severity: high
confidence: high
message: m
tests: {vulnerable: [a.sql], safe: [b.sql]}
"""
    assert "exactly one of 'check' or 'condition'" in "\n".join(_errors(base))
    both = base + "check: 'a.b:c'\ncondition: 'True'\n"
    assert "exactly one of 'check' or 'condition'" in "\n".join(_errors(both))


def test_invalid_yaml_and_shapes() -> None:
    assert "invalid YAML" in _errors("a: [unclosed")[0]
    assert "expected a mapping" in _errors("- 1\n- 2\n")[0]
    assert _errors("") == []


def test_pattern_not_accepts_string_or_list() -> None:
    text = GOOD + "pattern-not: \"$M.objects.raw('x')\"\n"
    rules, errs = parse_rules(text, "r.yml")
    assert errs == [] and len(rules[0].pattern_not) == 1  # type: ignore[union-attr]


def test_load_rules_reports_all_errors_and_duplicates(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(GOOD)
    (tmp_path / "b.yml").write_text(GOOD)
    (tmp_path / "c.yml").write_text(
        GOOD.replace("id: dj-raw-sql-interp", "id: dj-other").replace(
            "severity: high", "severity: nope"
        )
    )
    with pytest.raises(RuleLoadError) as info:
        load_rules([tmp_path])
    messages = "\n".join(str(e) for e in info.value.errors)
    assert "duplicate id" in messages and "c.yml" in messages


def test_load_rules_ok(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(GOOD)
    assert [r.id for r in load_rules([tmp_path])] == ["dj-raw-sql-interp"]
