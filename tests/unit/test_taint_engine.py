"""Intra-function taint engine: vulnerable/safe cases across Python, JS and PHP."""

from __future__ import annotations

import pytest

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.taint import analyze_function
from vulnfab.core.taintspec import SpecError, TaintSpec, parse_matcher

PY_SPEC = TaintSpec.from_rule(
    ["field request.args", "field request.form", "call input", "param user_*"],
    ["call cursor.execute arg0", "call os.system", "call eval"],
    ["call int", "call escape", "call shlex.quote"],
    [],
)
JS_SPEC = TaintSpec.from_rule(
    ["field req.query", "field req.body", "field req.params"],
    ["call db.query arg0", "call eval", "assign *.innerHTML"],
    ["call parseInt", "call Number", "call escapeHtml"],
    [],
)
PHP_SPEC = TaintSpec.from_rule(
    ["var _GET", "var _POST"],
    ["call mysqli_query arg1", "call system", "call eval"],
    ["call intval", "call htmlspecialchars", "call escapeshellarg"],
    [],
)


def hits(code: str, lang: str, spec: TaintSpec):
    ext = {"python": "py", "javascript": "js", "php": "php"}[lang]
    pf = parse_file(SourceFile(f"t.{ext}", lang, code, "0" * 64))
    out = []
    for fn in lower_file(pf).functions:
        out.extend(analyze_function(fn, spec, pf.path))
    return out


PY_VULN = {
    "direct": "def f():\n    q = request.args['id']\n    cursor.execute(q)\n",
    "concat": "def f():\n    q = 'select ' + request.args['id']\n    cursor.execute(q)\n",
    "fstring": "def f():\n    v = request.form['a']\n    cursor.execute(f'select {v}')\n",
    "reassign": "def f():\n    q = 'x'\n    q = request.args['id']\n    cursor.execute(q)\n",
    "branch_one_side": (
        "def f(c):\n    q = 'x'\n    if c:\n        q = request.args['id']\n    cursor.execute(q)\n"
    ),
    "loop": (
        "def f(items):\n    q = ''\n    for i in items:\n        q = q + request.args['id']\n"
        "    cursor.execute(q)\n"
    ),
    "param": "def f(user_id):\n    cursor.execute('a' + user_id)\n",
    "input_cmd": "def f():\n    c = input()\n    os.system(c)\n",
    "format_prop": "def f():\n    v = request.args['a']\n    cursor.execute('s {}'.format(v))\n",
    "chain": "def f():\n    a = request.args['a']\n    b = a\n    c = b\n    eval(c)\n",
    "sanitizer_other_var": (
        "def f():\n    a = request.args['a']\n    b = int(request.args['b'])\n    eval(a)\n"
    ),
    "sanitize_then_retaint": (
        "def f():\n    a = int(request.args['a'])\n    a = request.args['a']\n    eval(a)\n"
    ),
    "prefix_field": "def f():\n    os.system(request.args)\n",
    "in_nested_call": "def f():\n    os.system(str(request.args['a']))\n",
    "unknown_call_hops": "def f():\n    v = foo(request.args['a'])\n    eval(v)\n",
}
PY_SAFE = {
    "const": "def f():\n    cursor.execute('select 1')\n",
    "sanitized": "def f():\n    v = int(request.args['a'])\n    cursor.execute('s ' + str(v))\n",
    "sanitized_inline": "def f():\n    os.system('ls ' + shlex.quote(request.args['a']))\n",
    "overwritten": "def f():\n    q = request.args['a']\n    q = 'safe'\n    eval(q)\n",
    "wrong_arg": "def f():\n    cursor.execute('select 1', request.args['a'])\n",
    "untainted_param": "def f(other):\n    eval(other)\n",
    "branch_both_clean": (
        "def f(c):\n    if c:\n        q = int(request.args['a'])\n    else:\n        q = 1\n"
        "    eval(q)\n"
    ),
    "no_source": "def f():\n    a = 1\n    b = a + 2\n    eval(b)\n",
    "separate_functions": (
        "def f():\n    a = request.args['a']\n\ndef g():\n    a = 'x'\n    eval(a)\n"
    ),
    "sink_not_called": "def f():\n    a = request.args['a']\n    return a\n",
    "escape_reassign": "def f():\n    a = escape(request.args['a'])\n    eval(a)\n",
}

JS_VULN = {
    "query": "function f(req){ const q = req.query.id; db.query(q); }\n",
    "template": "function f(req){ db.query(`select ${req.body.x}`); }\n",
    "concat": "function f(req){ db.query('a' + req.params.id); }\n",
    "innerhtml": "function f(req, el){ el.innerHTML = req.query.name; }\n",
    "eval_chain": "function f(req){ let a = req.body; let b = a; eval(b); }\n",
    "branch": "function f(req, c){ let q = 'x'; if (c) { q = req.query.id; } db.query(q); }\n",
    "loop": (
        "function f(req, xs){ let q = ''; for (const x of xs) { q += req.query.id; } "
        "db.query(q); }\n"
    ),
}
JS_SAFE = {
    "const": "function f(req){ db.query('select 1'); }\n",
    "parseint": "function f(req){ const n = parseInt(req.query.id); db.query('a' + n); }\n",
    "overwritten": "function f(req){ let q = req.query.id; q = 'x'; db.query(q); }\n",
    "innerhtml_const": "function f(el){ el.innerHTML = '<b>x</b>'; }\n",
    "innerhtml_escaped": "function f(req, el){ el.innerHTML = escapeHtml(req.query.n); }\n",
    "second_arg": "function f(req){ db.query('a', [req.query.id]); }\n",
}

PHP_VULN = {
    "get": "<?php\nfunction f($c){ $id = $_GET['id']; mysqli_query($c, $id); }\n",
    "concat": "<?php\nfunction f($c){ mysqli_query($c, \"select \" . $_POST['x']); }\n",
    "system": "<?php\nfunction f(){ system($_GET['cmd']); }\n",
    "interp": '<?php\nfunction f($c){ mysqli_query($c, "select $_GET[id]"); }\n',
}
PHP_SAFE = {
    "intval": "<?php\nfunction f($c){ $i = intval($_GET['id']); mysqli_query($c, \"s $i\"); }\n",
    "const": "<?php\nfunction f($c){ mysqli_query($c, 'select 1'); }\n",
    "escapeshell": "<?php\nfunction f(){ system(escapeshellarg($_GET['c'])); }\n",
    "first_arg_only": "<?php\nfunction f($c){ mysqli_query($_GET['x'], 'select 1'); }\n",
}


@pytest.mark.parametrize("name", sorted(PY_VULN))
def test_python_vulnerable(name: str) -> None:
    assert hits(PY_VULN[name], "python", PY_SPEC), name


@pytest.mark.parametrize("name", sorted(PY_SAFE))
def test_python_safe(name: str) -> None:
    assert not hits(PY_SAFE[name], "python", PY_SPEC), name


@pytest.mark.parametrize("name", sorted(JS_VULN))
def test_js_vulnerable(name: str) -> None:
    assert hits(JS_VULN[name], "javascript", JS_SPEC), name


@pytest.mark.parametrize("name", sorted(JS_SAFE))
def test_js_safe(name: str) -> None:
    assert not hits(JS_SAFE[name], "javascript", JS_SPEC), name


@pytest.mark.parametrize("name", sorted(PHP_VULN))
def test_php_vulnerable(name: str) -> None:
    assert hits(PHP_VULN[name], "php", PHP_SPEC), name


@pytest.mark.parametrize("name", sorted(PHP_SAFE))
def test_php_safe(name: str) -> None:
    assert not hits(PHP_SAFE[name], "php", PHP_SPEC), name


def test_trace_starts_at_source_and_ends_at_sink() -> None:
    (hit,) = hits(PY_VULN["chain"], "python", PY_SPEC)
    assert hit.trace[0].kind == "source"
    assert hit.trace[-1].kind == "sink"
    assert hit.line == 5
    assert hit.function == "f"


def test_direct_flow_has_no_unresolved_hops() -> None:
    (hit,) = hits(PY_VULN["concat"], "python", PY_SPEC)
    assert hit.hops == 0


def test_unknown_call_adds_hop() -> None:
    (hit,) = hits(PY_VULN["unknown_call_hops"], "python", PY_SPEC)
    assert hit.hops >= 1


def test_known_propagator_adds_no_hop() -> None:
    (hit,) = hits(PY_VULN["format_prop"], "python", PY_SPEC)
    assert hit.hops == 0


def test_same_sink_reported_once() -> None:
    code = "def f(c):\n    q = request.args['a']\n    if c:\n        q = q + 'x'\n    eval(q)\n"
    assert len(hits(code, "python", PY_SPEC)) == 1


@pytest.mark.parametrize(
    "bad", ["", "call", "bogus x", "call a b c", "field x arg0", "call x nope"]
)
def test_bad_matchers_rejected(bad: str) -> None:
    with pytest.raises(SpecError):
        parse_matcher(bad, sink=True)
