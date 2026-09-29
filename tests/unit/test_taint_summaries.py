"""Intra-file function summaries (WP-5.4): param->return, param->sink, source->return."""
# ruff: noqa: E501

from __future__ import annotations

import pytest

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.taint import ModuleAnalysis
from vulnfab.core.taintspec import TaintSpec

PY = TaintSpec.from_rule(
    ["field request.args"], ["call cursor.execute arg0", "call os.system"], ["call int"], []
)
JS = TaintSpec.from_rule(
    ["field req.query"], ["call db.query arg0", "call eval"], ["call Number"], []
)
PHP = TaintSpec.from_rule(["var _GET"], ["call system"], ["call intval"], [])


def run(code: str, lang: str, spec: TaintSpec):
    ext = {"python": "py", "javascript": "js", "php": "php"}[lang]
    pf = parse_file(SourceFile(f"t.{ext}", lang, code, "0" * 64))
    return ModuleAnalysis(lower_file(pf), spec).run()


PY_VULN = {
    "param_to_sink": (
        "def run(q):\n    cursor.execute(q)\n\ndef view():\n    run(request.args['a'])\n"
    ),
    "return_flow": (
        "def ident(x):\n    return x\n\ndef view():\n    v = ident(request.args['a'])\n    os.system(v)\n"
    ),
    "two_levels": (
        "def inner(q):\n    os.system(q)\n\ndef mid(q):\n    inner(q)\n\n"
        "def view():\n    mid(request.args['a'])\n"
    ),
    "source_return": (
        "def get():\n    return request.args['a']\n\ndef view():\n    os.system(get())\n"
    ),
    "method_self": (
        "class A:\n    def sink(self, q):\n        os.system(q)\n\n"
        "    def view(self):\n        self.sink(request.args['a'])\n"
    ),
    "kwarg": (
        "def run(a, q):\n    os.system(q)\n\ndef view():\n    run(a=1, q=request.args['a'])\n"
    ),
    "concat_in_callee": (
        "def build(x):\n    return 'ls ' + x\n\n"
        "def view():\n    os.system(build(request.args['a']))\n"
    ),
}
PY_SAFE = {
    "callee_sanitizes": (
        "def run(q):\n    os.system('x' + str(int(q)))\n\ndef view():\n    run(request.args['a'])\n"
    ),
    "callee_ignores_param": (
        "def ident(x):\n    return 'const'\n\ndef view():\n    os.system(ident(request.args['a']))\n"
    ),
    "clean_arg": "def run(q):\n    os.system(q)\n\ndef view():\n    run('ls')\n",
    "other_param": (
        "def run(a, q):\n    os.system(q)\n\ndef view():\n    run(request.args['a'], 'ls')\n"
    ),
    "recursion_terminates": ("def f(x):\n    return f(x)\n\ndef view():\n    os.system(f('ok'))\n"),
    "ambiguous_name_unresolved_clean": "def view():\n    os.system(unknown('ls'))\n",
}


@pytest.mark.parametrize("name", sorted(PY_VULN))
def test_python_vuln(name: str) -> None:
    assert run(PY_VULN[name], "python", PY), name


@pytest.mark.parametrize("name", sorted(PY_SAFE))
def test_python_safe(name: str) -> None:
    assert not run(PY_SAFE[name], "python", PY), name


def test_hit_reported_at_sink_inside_callee_with_full_trace() -> None:
    (hit,) = run(PY_VULN["param_to_sink"], "python", PY)
    assert hit.line == 2
    assert hit.function == "run"
    kinds = [s.kind for s in hit.trace]
    assert kinds[0] == "source" and kinds[-1] == "sink" and "call" in kinds
    assert hit.hops == 0


def test_two_level_chain_reports_deepest_sink_once() -> None:
    hits = run(PY_VULN["two_levels"], "python", PY)
    assert [h.line for h in hits] == [2]


def test_recursion_does_not_hang() -> None:
    code = "def a(x):\n    return b(x)\n\ndef b(x):\n    return a(x)\n\ndef v():\n    os.system(a(request.args['q']))\n"
    assert run(code, "python", PY)  # unresolved cycle falls back to hop-propagation


def test_js_method_and_function() -> None:
    code = (
        "class B { q(x){ db.query(x); } run(req){ this.q(req.query.a); } }\n"
        "function h(x){ return x; }\nfunction v(req){ eval(h(req.query.b)); }\n"
    )
    assert sorted(h.line for h in run(code, "javascript", JS)) == [1, 3]


def test_js_sanitizer_in_callee() -> None:
    code = "function q(x){ db.query('a' + Number(x)); }\nfunction v(req){ q(req.query.a); }\n"
    assert not run(code, "javascript", JS)


def test_php_function_summary() -> None:
    code = "<?php\nfunction run($c){ system($c); }\nfunction v(){ run($_GET['a']); }\n"
    assert [h.line for h in run(code, "php", PHP)] == [2]
    safe = "<?php\nfunction run($c){ system(intval($c)); }\nfunction v(){ run($_GET['a']); }\n"
    assert not run(safe, "php", PHP)
