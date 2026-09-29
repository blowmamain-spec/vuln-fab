# ruff: noqa: E501
"""Golden tests for the TIR front-ends (WP-5.1)."""

from __future__ import annotations

import pytest

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.tir import ModuleIR, format_module


def lower(language: str, code: str) -> ModuleIR:
    path = {"python": "a.py", "php": "a.php", "tsx": "a.tsx"}.get(language, "a.ts")
    return lower_file(parse_file(SourceFile(path, language, code, "0" * 64)))


def body(language: str, code: str, name: str = "f") -> list[str]:
    """Formatted body lines of function ``name`` (without the header)."""
    module = lower(language, code)
    fn = module.function(name)
    assert fn is not None, [f.qualname for f in module.functions]
    return [
        line.strip()
        for line in format_module(ModuleIR(module.file, module.language, [fn])).splitlines()[1:]
    ]  # noqa: E501


def module_body(language: str, code: str) -> list[str]:
    return body(language, code, "<module>")


# --- Python -------------------------------------------------------------------------------

PY = [
    ("assign+attr+subscript", "def f(req):\n    q = req.GET['q']\n", ["L2: q = req.GET['q']"]),
    ("fstring", "def f(a):\n    s = f'x{a}y'\n", ["L2: t1 = concat('x', a, 'y')", "L2: s = t1"]),
    ("concat", "def f(a):\n    s = 'x' + a\n", ["L2: t1 = concat('x', a)", "L2: s = t1"]),
    ("call+kwargs", "def f(a):\n    g(a, k=1)\n", ["L2: t1 = call g(a, k=1)"]),
    ("method call", "def f(a):\n    a.b.c(1)\n", ["L2: t1 = call a.b.c(1)"]),
    (
        "chained call",
        "def f(a):\n    a.x().y(2)\n",
        ["L2: t1 = call a.x()", "L2: t2 = call t1.y(2)"],
    ),
    ("aug assign", "def f(a):\n    a += 'x'\n", ["L2: t1 = concat(a, 'x')", "L2: a = t1"]),
    (
        "tuple unpack",
        "def f():\n    a, b = g()\n",
        ["L2: t1 = call g()", "L2: a = t1[0]", "L2: b = t1[1]"],
    ),
    ("chained assign", "def f():\n    a = b = 1\n", ["L2: b = 1", "L2: a = 1"]),
    ("return", "def f(a):\n    return a\n", ["L2: return a"]),
    (
        "if/else",
        "def f(a):\n    if a:\n        x = 1\n    else:\n        x = 2\n",
        ["L2: branch", "then:", "L3: x = 1", "else:", "L5: x = 2"],
    ),
    (
        "elif",
        "def f(a):\n    if a:\n        pass\n    elif b:\n        x = 1\n",
        ["L2: branch", "then:", "else:", "L4: branch", "L5: x = 1"],
    ),
    (
        "for",
        "def f(xs):\n    for x in xs:\n        g(x)\n",
        ["L2: loop", "L2: x = xs[?(iter)]", "L3: t1 = call g(x)"],
    ),
    (
        "while",
        "def f():\n    while g():\n        h()\n",
        ["L2: loop", "L2: t1 = call g()", "L3: t2 = call h()"],
    ),
    (
        "try/except",
        "def f():\n    try:\n        a()\n    except E:\n        b()\n",
        ["L3: t1 = call a()", "L4: branch", "L5: t2 = call b()"],
    ),
    (
        "with as",
        "def f():\n    with open(p) as fh:\n        g(fh)\n",
        ["L2: t1 = call open(p)", "L2: fh = t1", "L3: t2 = call g(fh)"],
    ),
    (
        "dict/list",
        "def f(a):\n    d = {'k': a}\n    l = [a, 1]\n",
        ["L2: t1 = concat(a)", "L2: d = t1", "L3: t2 = concat(a, 1)", "L3: l = t2"],
    ),
    (
        "ternary",
        "def f(a, b):\n    x = a if c else b\n",
        ["L2: t1 = concat(a, c, b)", "L2: x = t1"],
    ),
    ("comprehension", "def f(xs):\n    y = [g(x) for x in xs]\n", ["call g(x)"]),
    ("subscript assign", "def f(a):\n    d['k'] = a\n", ["L2: d['k'] = a"]),
    ("attr assign", "def f(a):\n    self.x = a\n", ["L2: self.x = a"]),
    ("await", "async def f(a):\n    x = await g(a)\n", ["L2: t1 = call g(a)", "L2: x = t1"]),
    ("lambda unknown", "def f():\n    g(lambda x: x)\n", ["call g(?(lambda))"]),
]


@pytest.mark.parametrize(("desc", "code", "expected"), PY, ids=[c[0] for c in PY])
def test_python(desc: str, code: str, expected: list[str]) -> None:
    lines = body("python", code)
    for want in expected:
        assert any(want in line for line in lines), f"{want!r} not in {lines}"


def test_python_functions_classes_decorators_imports() -> None:
    code = (
        "import os, sys as s\nfrom a.b import c as d, e\n\n"
        "@app.route('/x')\n@login_required\ndef view(req, n=1, *a, **k):\n    pass\n\n"
        "class K:\n    def m(self, x):\n        return x\n"
    )
    module = lower("python", code)
    view = module.function("view")
    assert view is not None and view.params == ("req", "n", "a", "k")
    assert view.decorators == ("app.route('/x')", "login_required")
    method = module.function("K.m")
    assert method is not None and method.class_name == "K" and method.params == ("self", "x")
    assert module.imports["os"] == ("os", "*") and module.imports["s"] == ("sys", "*")
    assert module.imports["d"] == ("a.b", "c") and module.imports["e"] == ("a.b", "e")


def test_python_module_level_code_goes_to_module_function() -> None:
    assert any("call setup()" in line for line in module_body("python", "setup()\n"))


# --- JavaScript / TypeScript --------------------------------------------------------------

JS = [
    (
        "member+call",
        "function f(req) { const a = req.query.id; g(a); }",
        ["a = req.query.id", "call g(a)"],
    ),
    ("template", "function f(a) { const s = `x${a}y${b}`; }", ["concat('x', a, 'y', b)"]),
    ("concat", "function f(a) { const s = 'x' + a + 'y'; }", ["concat('x', a)", "concat(t1, 'y')"]),
    (
        "destructure object",
        "function f(req) { const { id, name: n } = req.query; }",
        ["id = req.query.id", "n = req.query.name"],
    ),
    (
        "destructure default",
        "function f(req) { const { id, name = 'x' } = req.query; }",
        ["id = req.query.id", "name = req.query.name"],
    ),
    ("destructure array", "function f(xs) { const [a, b] = xs; }", ["a = xs[0]", "b = xs[1]"]),
    (
        "param pattern",
        "function f({ params }) { g(params); }",
        ["params = %arg0.params", "call g(params)"],
    ),
    (
        "chain",
        "function f(s) { s.from('t').select('*').eq('id', 1); }",
        ["call s.from('t')", "call t1.select('*')", "call t2.eq('id', 1)"],
    ),
    ("new", "function f(a) { const x = new Foo(a); }", ["call new Foo(a)"]),
    ("await+ts", "async function f(a: string) { const x = await g(a as any); }", ["call g(a)"]),
    ("non-null", "function f(a) { g(a!); }", ["call g(a)"]),
    ("assign member", "function f(el, a) { el.innerHTML = a; }", ["el.innerHTML = a"]),
    ("aug assign", "function f(a) { a += 'x'; }", ["concat(a, 'x')", "a = t1"]),
    (
        "if/else",
        "function f(a) { if (a) { x = 1 } else { x = 2 } }",
        ["branch", "then:", "x = 1", "else:", "x = 2"],
    ),
    (
        "for of",
        "function f(xs) { for (const x of xs) { g(x); } }",
        ["loop", "x = xs[?(iter)]", "call g(x)"],
    ),
    (
        "for classic",
        "function f() { for (let i = 0; i < 3; i++) { g(i); } }",
        ["loop", "call g(i)"],
    ),
    ("while", "function f() { while (g()) { h(); } }", ["loop", "call g()", "call h()"]),
    (
        "try/catch",
        "function f() { try { a(); } catch (e) { b(); } }",
        ["call a()", "branch", "call b()"],
    ),
    (
        "switch",
        "function f(a) { switch (a) { case 1: g(); break; default: h(); } }",
        ["branch", "call g()", "call h()"],
    ),
    ("ternary", "function f(a) { const x = a ? 'p' : 'q'; }", ["concat('p', 'q')"]),
    ("object literal", "function f(a) { const o = { k: a, b }; }", ["concat(a, b)"]),
    (
        "callback fn",
        "function f(app) { app.get('/x', (req, res) => { res.send(req.body); }); }",
        ["call app.get('/x', <anon@1>)"],
    ),
    ("arrow expr body", "const f = (a) => a + 1;", ["return t1"]),
    ("this/super", "function f() { this.x = 1; super.y(); }", ["this.x = 1", "call super.y()"]),
    (
        "optional numbers",
        "function f() { g(1, 2.5, true, null, undefined); }",
        ["call g(1, 2.5, True, None, None)"],
    ),
]


@pytest.mark.parametrize(("desc", "code", "expected"), JS, ids=[c[0] for c in JS])
def test_javascript(desc: str, code: str, expected: list[str]) -> None:
    name = "f"
    lines = body("typescript", code, name)
    for want in expected:
        assert any(want in line for line in lines), f"{want!r} not in {lines}"


def test_javascript_classes_and_named_arrow_functions() -> None:
    module = lower(
        "typescript", "class C { m(x) { return eval(x) } static s() {} }\nconst h = (a) => a;\n"
    )
    assert module.function("C.m") is not None and module.function("C.s") is not None
    assert module.function("h") is not None


def test_javascript_imports_and_tsx() -> None:
    module = lower(
        "tsx",
        "import a, { b as c } from './m';\nimport * as ns from 'lib';\nconst el = <div x={g()} />;\n",
    )
    assert module.imports == {"a": ("./m", "default"), "c": ("./m", "b"), "ns": ("lib", "*")}
    assert any("call g()" in line for line in module_body("tsx", "const el = <div x={g()} />;\n"))


# --- PHP ----------------------------------------------------------------------------------

PHP = [
    ("superglobal", "<?php function f() { $a = $_GET['id']; }", ["a = _GET['id']"]),
    (
        "interpolation",
        '<?php function f($n) { $s = "hi $n and {$n}"; }',
        ["concat('hi ', n, ' and ', n)"],
    ),
    ("concat dot", "<?php function f($a) { $s = 'x' . $a; }", ["concat('x', a)"]),
    ("function call", "<?php function f($a) { g($a, 1); }", ["call g(a, 1)"]),
    ("method call", "<?php function f($db) { $db->query('x'); }", ["call db.query('x')"]),
    ("chained", "<?php function f($db) { $db->a()->b(1); }", ["call db.a()", "call t1.b(1)"]),
    ("static call", "<?php function f($a) { DB::raw($a); }", ["call DB::raw(a)"]),
    ("new", "<?php function f($a) { $u = new User($a); }", ["call new User(a)"]),
    ("property", "<?php function f($o) { $x = $o->name; }", ["x = o.name"]),
    ("assign property", "<?php function f($o, $a) { $o->name = $a; }", ["o.name = a"]),
    ("assign index", "<?php function f($a) { $arr['k'] = $a; }", ["arr['k'] = a"]),
    ("array", "<?php function f($a) { $x = ['k' => $a, 2]; }", ["concat(a, 2)"]),
    ("echo", "<?php function f($a) { echo $a, 'x'; }", ["concat(a, 'x')", "call echo("]),
    ("return", "<?php function f($a) { return $a; }", ["return a"]),
    (
        "if/elseif/else",
        "<?php function f($a) { if ($a) { $x = 1; } elseif ($b) { $x = 2; } else { $x = 3; } }",
        ["branch", "x = 1", "x = 2", "x = 3"],
    ),
    (
        "foreach",
        "<?php function f($xs) { foreach ($xs as $k => $v) { g($v); } }",
        ["loop", "k = xs[?(iter)]", "v = xs[?(iter)]", "call g(v)"],
    ),
    ("while", "<?php function f() { while (g()) { h(); } }", ["loop", "call g()", "call h()"]),
    (
        "try/catch",
        "<?php function f() { try { a(); } catch (Exception $e) { b(); } }",
        ["call a()", "branch", "call b()"],
    ),
    ("include", "<?php function f($p) { include $p; }", ["call include(p)"]),
    ("shell backtick", "<?php function f($p) { $o = `ls $p`; }", ["call shell_exec("]),
    (
        "closure arg",
        "<?php function f($app) { $app->get('/x', function ($req) { return $req; }); }",
        ["call app.get('/x', <anon@1>)"],
    ),
    ("aug assign", "<?php function f($a) { $a .= 'x'; }", ["concat(a, 'x')"]),
    ("named args", "<?php function f($a) { g(name: $a); }", ["call g(name=a)"]),
]


@pytest.mark.parametrize(("desc", "code", "expected"), PHP, ids=[c[0] for c in PHP])
def test_php(desc: str, code: str, expected: list[str]) -> None:
    lines = body("php", code)
    for want in expected:
        assert any(want in line for line in lines), f"{want!r} not in {lines}"


def test_php_classes_and_params() -> None:
    module = lower(
        "php", "<?php class C { public function m(Request $r, $id = 1, ...$rest) { return $id; } }"
    )
    method = module.function("C.m")
    assert method is not None and method.class_name == "C" and method.params[:2] == ("r", "id")


# --- robustness ----------------------------------------------------------------------------


def test_deeply_nested_expression_does_not_overflow() -> None:
    code = "def f():\n    x = " + "(" * 100 + "1" + ")" * 100 + "\n"
    assert lower("python", code).function("f") is not None
    deep = "def f():\n    x = " + "a + " * 300 + "b\n"
    module = lower("python", deep)  # left-deep binary chain: guarded, no RecursionError
    assert module.function("f") is not None


def test_unhandled_constructs_are_counted_not_dropped() -> None:
    module = lower("python", "def f(a):\n    match a:\n        case 1:\n            g()\n")
    assert sum(module.unhandled.values()) >= 1
    assert any(
        "call g()" in line
        for line in body("python", "def f(a):\n    match a:\n        case 1:\n            g()\n")
    )
