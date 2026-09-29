from pathlib import Path

from typer.testing import CliRunner

from vulnfab.cli import app
from vulnfab.core.rules import parse_rules
from vulnfab.core.ruletest import annotated_lines, run_rule_tests

RULE = """
id: py-eval
stack: generic
languages: [python]
severity: high
confidence: medium
cwe: [CWE-95]
message: "eval() dengan input."
pattern: "eval($X)"
tests:
  vulnerable: [vuln.py]
  safe: [safe.py]
"""


def _setup(tmp_path: Path, vuln: str, safe: str) -> Path:
    root = tmp_path / "tests"
    (root / "py-eval").mkdir(parents=True)
    (root / "py-eval" / "vuln.py").write_text(vuln)
    (root / "py-eval" / "safe.py").write_text(safe)
    return root


def _rule():  # type: ignore[no-untyped-def]
    rules, errs = parse_rules(RULE, "r.yml")
    assert not errs
    return rules[0]


def test_annotations() -> None:
    text = "a\neval(x)  # vuln: py-eval\nb  # vuln: other-rule\n// vuln: py-eval\n"
    assert annotated_lines(text, "py-eval") == {2, 4}


def test_passing_rule(tmp_path: Path) -> None:
    root = _setup(
        tmp_path,
        "eval(a)  # vuln: py-eval\nx = 1\neval(b)  # vuln: py-eval\n",
        "ast.literal_eval(a)\n",
    )  # noqa: E501
    result = run_rule_tests(_rule(), root)
    assert result.ok, result.problems


def test_missed_and_unexpected_findings(tmp_path: Path) -> None:
    root = _setup(tmp_path, "eval(a)\nfoo(b)  # vuln: py-eval\n", "x = 1\n")
    problems = "\n".join(run_rule_tests(_rule(), root).problems)
    assert "not reported at line(s) [2]" in problems
    assert "unexpected finding at line(s) [1]" in problems


def test_safe_file_with_finding_fails(tmp_path: Path) -> None:
    root = _setup(tmp_path, "eval(a)  # vuln: py-eval\n", "eval(a)\n")
    problems = run_rule_tests(_rule(), root).problems
    assert any("safe file produced finding" in p for p in problems)


def test_vulnerable_file_without_annotations(tmp_path: Path) -> None:
    root = _setup(tmp_path, "eval(a)\n", "x = 1\n")
    problems = run_rule_tests(_rule(), root).problems
    assert any("no '# vuln: py-eval' annotation" in p for p in problems)


def test_missing_files_and_wrong_language(tmp_path: Path) -> None:
    root = tmp_path / "tests"
    (root / "py-eval").mkdir(parents=True)
    (root / "py-eval" / "vuln.py").write_text("eval(a)  # vuln: py-eval\n")
    problems = "\n".join(run_rule_tests(_rule(), root).problems)
    assert "missing test file" in problems and "safe.py" in problems
    (root / "py-eval" / "safe.py").write_text("x = 1\n")
    rule_js = RULE.replace("vuln.py", "vuln.js")
    rules, _ = parse_rules(rule_js, "r.yml")
    (root / "py-eval" / "vuln.js").write_text("eval(a) // vuln: py-eval\n")
    assert "not in rule languages" in "\n".join(run_rule_tests(rules[0], root).problems)


def test_broken_pattern_is_reported(tmp_path: Path) -> None:
    rules, _ = parse_rules(RULE.replace('"eval($X)"', '"eval($X"'), "r.yml")
    root = _setup(tmp_path, "eval(a)  # vuln: py-eval\n", "x = 1\n")
    assert any("not valid python" in p for p in run_rule_tests(rules[0], root).problems)


def test_cli_rules_test(tmp_path: Path) -> None:
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "r.yml").write_text(RULE.replace("py-eval", "tt-eval"))
    root = tmp_path / "tests"
    (root / "tt-eval").mkdir(parents=True)
    (root / "tt-eval" / "vuln.py").write_text("eval(a)  # vuln: tt-eval\n")
    (root / "tt-eval" / "safe.py").write_text("x = 1\n")
    runner = CliRunner()
    args = ["rules", "test", "--rule", "tt-eval", "--rules", str(packs), "--tests-root", str(root)]
    ok = runner.invoke(app, args)
    assert ok.exit_code == 0 and "PASS tt-eval" in ok.output
    (root / "tt-eval" / "safe.py").write_text("eval(a)\n")
    bad = runner.invoke(app, args)
    assert bad.exit_code == 1 and "FAIL tt-eval" in bad.output
    unknown = runner.invoke(app, ["rules", "test", "--rule", "nope", "--tests-root", str(root)])
    assert unknown.exit_code == 2
    listing = runner.invoke(app, ["rules", "list", "--rules", str(packs)])
    assert "tt-eval" in listing.output and "py-eval" in listing.output
