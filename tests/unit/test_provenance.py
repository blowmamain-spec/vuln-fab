"""Benign-provenance demotion of "non-constant argument" heuristics."""
# ruff: noqa: E501

from __future__ import annotations

from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.lower import lower_file
from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.provenance import line_is_benign, pure_locals


def fn_of(code: str, lang: str = "javascript", name: str = "f"):  # type: ignore[no-untyped-def]
    pf = parse_file(SourceFile("t.js" if lang == "javascript" else "t.py", lang, code, "0" * 64))
    return next(fn for fn in lower_file(pf).functions if fn.name == name)


def test_constants_and_pure_calls_are_benign() -> None:
    fn = fn_of(
        "function f(){ const a = Math.floor(Math.random() * 10); const b = a.toString();"
        " const e = a + '+' + b; return eval(e); }"
    )
    assert {"a", "b", "e"} <= pure_locals(fn)
    assert line_is_benign(fn, 1)


def test_params_and_unknown_calls_are_not_benign() -> None:
    assert not pure_locals(fn_of("function f(x){ const y = x + 1; return y; }")) & {"x", "y"}
    fn = fn_of("function f(){ const u = getUser(); const c = u.name; return eval(c); }")
    assert "c" not in pure_locals(fn)
    assert not line_is_benign(fn, 1)


def test_one_impure_assignment_taints_the_variable() -> None:
    fn = fn_of("function f(req){ let e = '1+1'; if (req) { e = req.q; } return eval(e); }")
    assert "e" not in pure_locals(fn)


def test_python_flow() -> None:
    fn = fn_of(
        "import random\ndef f():\n    n = random.randint(1, 9)\n    e = str(n) + '+1'\n    return eval(e)\n",
        "python",
    )
    assert {"n", "e"} <= pure_locals(fn) and line_is_benign(fn, 5)


def test_scan_demotes_only_benign_eval(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "function captcha() {\n  const t = Math.floor(Math.random() * 10);\n  const e = t + '+' + t;\n  return eval(e);\n}\n"
        "function other(user) {\n  return eval(user.expr);\n}\n"
    )
    result = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW))
    by_line = {f.line: f for f in result.findings if f.rule_id.endswith("eval")}
    assert by_line[4].confidence is Confidence.LOW and "constants and pure" in by_line[4].message
    assert by_line[7].confidence is not Confidence.LOW
