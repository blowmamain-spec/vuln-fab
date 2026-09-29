"""Matcher tests: >= 30 cases per language plus rule-level features (WP-2.3)."""

from __future__ import annotations

import pytest

from vulnfab.core.matcher import (
    FileIndex,
    PatternError,
    compile_pattern,
    compile_rule,
    match_at,
    run_rule,
)
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import node_lines, parse_file, walk
from vulnfab.core.rules import PatternRule, parse_rules


def _parse(language: str, code: str):  # type: ignore[no-untyped-def]
    return parse_file(SourceFile("t", language, code, "0" * 64))


def count(language: str, pattern: str, code: str) -> int:
    pat = compile_pattern(language, pattern)
    pf = _parse(language, code)
    return sum(1 for n in walk(pf.tree.root_node) if match_at(pat, n) is not None)


PY = [
    ("eval($X)", "eval(user)", 1),
    ("eval($X)", "evaluate(user)", 0),
    ("eval($X)", "eval(a, b)", 0),
    ("eval($X)", "x = eval(a + b)", 1),
    ("eval($X)", "def f():\n    return eval(a)", 1),
    ("eval($X)", "eval(a)\neval(b)", 2),
    ("eval($X)", "x = 'eval(a)'", 0),
    ("eval($X)", "# eval(a)\npass", 0),
    ("eval(...)", "eval()", 1),
    ("eval(...)", "eval(a, b, c)", 1),
    ("$M.objects.raw($Q)", "User.objects.raw(q)", 1),
    ("$M.objects.raw($Q)", "User.objects.filter(q)", 0),
    ("$M.objects.raw($Q)", "objects.raw(q)", 0),
    ("$M.objects.raw($Q)", "a.b.objects.raw(q)", 1),
    ("subprocess.run(..., shell=True)", "subprocess.run(cmd, shell=True)", 1),
    ("subprocess.run(..., shell=True)", "subprocess.run(cmd, shell=False)", 0),
    ("subprocess.run(..., shell=True)", "subprocess.run(a, b, cwd=x, shell=True)", 1),
    ("subprocess.run(..., shell=True)", "subprocess.run(shell=True)", 1),
    ("subprocess.run(..., shell=True)", "subprocess.run(cmd)", 0),
    ("subprocess.run($C, ...)", "subprocess.run(cmd)", 1),
    ("subprocess.run($C, ...)", "subprocess.run(cmd, check=True)", 1),
    ("$X == $X", "a == a", 1),
    ("$X == $X", "a == b", 0),
    ("$X == $X", "f(1) == f(1)", 1),
    ("f($X, $Y)", "f(a)", 0),
    ("f($X, $Y)", "f(a, b)", 1),
    ("f($X)", "f(g(h(1)))", 1),
    ("yaml.load($X)", "yaml.load(data)", 1),
    ("yaml.load($X)", "yaml.safe_load(data)", 0),
    ("hashlib.md5(...)", "hashlib.md5(b'x').hexdigest()", 1),
    ("open($P, 'w')", "open(path, 'w')", 1),
    ("open($P, 'w')", 'open(path, "w")', 1),
    ("open($P, 'w')", "open(path, 'r')", 0),
    ("$A = $B", "x = 1", 1),
    ("pickle.loads($X)", "import pickle\nd = pickle.loads(blob)", 1),
    ("def $F(...):\n    ...", "def go(a, b):\n    return a", 1),
    ("class $C(...):\n    ...", "class A(Base):\n    x = 1", 1),
]

JS = [
    ("eval($X)", "eval(input)", 1),
    ("eval($X)", "myeval(input)", 0),
    ("eval($X)", "const s = 'eval(a)'", 0),
    ("eval($X)", "// eval(a)\nlet z;", 0),
    ("eval($X)", "eval(a);\neval(b);", 2),
    ("$EL.innerHTML = $X", "el.innerHTML = user", 1),
    ("$EL.innerHTML = $X", "el.textContent = user", 0),
    ("$EL.innerHTML = $X", "el.innerHTML += x", 0),
    ("document.write($X)", "document.write(x)", 1),
    ("child_process.exec($X)", "child_process.exec(cmd)", 1),
    ("child_process.exec($X)", "child_process.execFile(cmd)", 0),
    ("supabase.from($T).select(...)", "supabase.from('a').select('*').eq('id', 1)", 1),
    ("supabase.from($T).select(...)", "supabase.from('a').insert({})", 0),
    ("supabase.from($T).select(...)", "supabase.from(t).select()", 1),
    ("new Function($X)", "const f = new Function(code)", 1),
    ("new Function($X)", "const f = Function(code)", 0),
    ("$X.or(...)", "q.or(`a.eq.${v}`)", 1),
    ("$X.or(...)", "q.and(`a`)", 0),
    ("fetch($U, ...)", "fetch(url, {method: 'POST'})", 1),
    ("fetch($U, ...)", "fetch(url)", 1),
    ("fetch($U)", "fetch(url, {a: 1})", 0),
    ("$F($X)", "foo(bar)", 1),
    ("setTimeout($X, ...)", "setTimeout('alert(1)', 100)", 1),
    ("localStorage.setItem($K, $V)", "localStorage.setItem('token', t)", 1),
    ("JSON.parse($X)", "const d = JSON.parse(req.body)", 1),
    ("$A.$B($C)", "obj.method(arg)", 1),
    ("$A.$B($C)", "fn(arg)", 0),
    ("$X === $X", "a === a", 1),
    ("$X === $X", "a === b", 0),
    ("require('child_process')", "const cp = require('child_process')", 1),
    ("require('child_process')", 'const cp = require("child_process")', 1),
    ("require('child_process')", "const cp = require('fs')", 0),
    ("await $X.json()", "const j = await res.json()", 1),
    ("res.send($X)", "res.send(`hi ${name}`)", 1),
    ("app.get($P, ...)", "app.get('/x', (req, res) => {})", 1),
]

TS = [
    ("eval($X)", "eval(input as string)", 1),
    ("$EL.innerHTML = $X", "(el as HTMLElement).innerHTML = user", 1),
    ("exec($X)", "import { exec } from 'child_process';\nexec(cmd);", 1),
    ("supabase.from($T).select(...)", "await supabase.from<Row>('a').select('*')", 1),
    ("createClient($U, $K)", "createClient(url, process.env.KEY!)", 1),
    ("createClient($U, $K)", "createClient(url)", 0),
    (
        "createClient($U, process.env.NEXT_PUBLIC_SERVICE_KEY!)",
        "createClient(u, process.env.NEXT_PUBLIC_SERVICE_KEY!)",
        1,
    ),  # noqa: E501
]

PHP = [
    ("eval($X)", "eval($code);", 1),
    ("unserialize($X)", "$o = unserialize($_GET['d']);", 1),
    ("unserialize($X)", "$o = json_decode($d);", 0),
    ("unserialize($X)", "// unserialize($x)\n$a = 1;", 0),
    ("DB::raw($X)", "DB::raw($sql);", 1),
    ("DB::raw($X)", "DB::table($sql);", 0),
    ("DB::raw($X)", "$x = DB::raw($a . $b);", 1),
    ("$request->input(...)", "$id = $request->input('id');", 1),
    ("$request->input(...)", "$id = $request->query('id');", 0),
    ("$request->input(...)", "$id = $req->input('id');", 0),
    ("exec($X)", "exec($cmd, $out);", 0),
    ("exec($X, ...)", "exec($cmd, $out);", 1),
    ("exec($X, ...)", "exec($cmd);", 1),
    ("$DB->whereRaw($X)", "$q->whereRaw($cond);", 1),
    ("$DB->whereRaw($X)", "$q->where($cond);", 0),
    ("$_GET[$K]", "$a = $_GET['id'];", 1),
    ("$_GET[$K]", "$a = $_POST['id'];", 0),
    ("$_POST[$K]", "echo $_POST['x'];", 1),
    ("echo $X;", "echo $name;", 1),
    ("echo $X;", "print($name);", 0),
    ("system($X)", "system($_GET['c']);", 1),
    ("shell_exec($X)", "$r = shell_exec($cmd);", 1),
    ("md5($X)", "$h = md5($pw);", 1),
    ("mysqli_query($C, $Q)", "mysqli_query($conn, 'select 1');", 1),
    ("mysqli_query($C, $Q)", "mysqli_query($conn);", 0),
    ("include($X);", "include($page);", 1),
    ("include $X;", "include $page;", 1),
    ("new $C(...)", "$o = new Foo(1, 2);", 1),
    ("file_get_contents($X)", "file_get_contents('a.txt');", 1),
    ("$X->save()", "$user->save();", 1),
    ("$X->save()", "$user->save($opts);", 0),
    ("Route::get($P, ...)", "Route::get('/a', [C::class, 'i']);", 1),
    ("Route::get($P, ...)", "Route::post('/a', fn() => 1);", 0),
    ("header('Location: ' . $X)", "header('Location: ' . $url);", 1),
    ("$this->$M($X)", "$this->foo($bar);", 1),
]


@pytest.mark.parametrize(("pattern", "code", "expected"), PY)
def test_python(pattern: str, code: str, expected: int) -> None:
    assert count("python", pattern, code) == expected


@pytest.mark.parametrize(("pattern", "code", "expected"), JS)
def test_javascript(pattern: str, code: str, expected: int) -> None:
    assert count("javascript", pattern, code) == expected


@pytest.mark.parametrize(("pattern", "code", "expected"), TS)
def test_typescript(pattern: str, code: str, expected: int) -> None:
    assert count("typescript", pattern, code) == expected


@pytest.mark.parametrize(("pattern", "code", "expected"), PHP)
def test_php(pattern: str, code: str, expected: int) -> None:
    assert count("php", pattern, "<?php " + code) == expected


def test_case_counts_meet_acceptance() -> None:
    assert len(PY) >= 30 and len(PHP) >= 30
    assert len(JS) + len(TS) >= 30


# --- pattern compilation errors and binding -------------------------------------------------


def test_invalid_pattern_is_rejected() -> None:
    with pytest.raises(PatternError, match="not valid python"):
        compile_pattern("python", "eval($X")
    with pytest.raises(PatternError, match="single"):
        compile_pattern("python", "a = 1\nb = 2")
    with pytest.raises(PatternError, match="no parser"):
        compile_pattern("sql", "select 1")


def test_metavariable_binds_subtree() -> None:
    pat = compile_pattern("python", "$M.objects.raw($Q)")
    pf = _parse("python", "User.objects.raw(f'select {x}')")
    node = next(n for n in walk(pf.tree.root_node) if match_at(pat, n) is not None)
    env = match_at(pat, node)
    assert env is not None
    assert env["M"].text == b"User" and env["Q"].type == "string"


def test_ellipsis_inside_string_is_literal_text() -> None:
    assert count("python", "print('...')", "print('...')") == 1
    assert count("python", "print('...')", "print('a')") == 0


def test_php_superglobal_is_not_a_metavariable() -> None:
    assert count("php", "$_GET['a']", "<?php $x = $_GET['a'];") == 1
    assert count("php", "$_GET['a']", "<?php $x = $_GET['b'];") == 0


def test_quote_style_does_not_matter() -> None:
    assert count("javascript", 'f("a")', "f('a')") == 1
    assert count("python", "f('a')", 'f("a")') == 1


# --- rule-level features --------------------------------------------------------------------


def _rule(body: str, languages: str = "[python]") -> PatternRule:
    text = f"""
id: t-rule
stack: generic
languages: {languages}
severity: high
confidence: medium
message: m
tests: {{vulnerable: [a], safe: [b]}}
{body}
"""
    rules, errs = parse_rules(text, "t.yml")
    assert errs == [], errs
    rule = rules[0]
    assert isinstance(rule, PatternRule)
    return rule


def run(rule: PatternRule, code: str, language: str = "python") -> list[int]:
    crule = compile_rule(rule)
    pf = _parse(language, code)
    index = FileIndex(pf.tree)
    return [node_lines(m.node, pf.source)[0] for m in run_rule(crule, language, index)]


def test_pattern_either() -> None:
    rule = _rule('pattern-either:\n  - "eval($X)"\n  - "exec($X)"')
    assert run(rule, "eval(a)\nexec(b)\nprint(c)") == [1, 2]


def test_pattern_not() -> None:
    rule = _rule('pattern: "eval($X)"\npattern-not: "eval(\'1\')"')
    assert run(rule, "eval(a)\neval('1')\neval('2')") == [1, 3]


def test_pattern_inside_and_not_inside() -> None:
    inside = _rule('pattern: "eval($X)"\npattern-inside: "def $F(...):\\n    ..."')
    assert run(inside, "eval(a)\ndef f():\n    eval(b)") == [3]
    outside = _rule('pattern: "eval($X)"\npattern-not-inside: "def $F(...):\\n    ..."')
    assert run(outside, "eval(a)\ndef f():\n    eval(b)") == [1]


def test_where_fstring_or_concat() -> None:
    rule = _rule(
        'pattern: "$M.objects.raw($Q)"\nwhere:\n  - {metavariable: Q, kind: fstring_or_concat}'
    )  # noqa: E501
    code = (
        "A.objects.raw(f'select {x}')\n"
        "A.objects.raw('select ' + x)\n"
        "A.objects.raw('select %s' % x)\n"
        "A.objects.raw('select {}'.format(x))\n"
        "A.objects.raw('select 1')\n"
        "A.objects.raw('a' + 'b')\n"
        "A.objects.raw(q)\n"
        "A.objects.raw(f'no interpolation')\n"
    )
    assert run(rule, code) == [1, 2, 3, 4]


def test_where_literal_identifier_regex() -> None:
    lit = _rule('pattern: "f($X)"\nwhere:\n  - {metavariable: X, kind: literal}')
    assert run(lit, "f(1)\nf('a')\nf(x)\nf(x + 1)\nf(f'{y}')") == [1, 2]
    not_lit = _rule('pattern: "f($X)"\nwhere:\n  - {metavariable: X, kind: not_literal}')
    assert run(not_lit, "f(1)\nf(x)\nf(x + 1)") == [2, 3]
    ident = _rule('pattern: "f($X)"\nwhere:\n  - {metavariable: X, kind: identifier}')
    assert run(ident, "f(1)\nf(x)\nf(x.y)") == [2]
    rx = _rule('pattern: "f($X)"\nwhere:\n  - {metavariable: X, kind: regex, regex: "^pass"}')
    assert run(rx, "f(password)\nf(user)") == [1]
    nrx = _rule('pattern: "f($X)"\nwhere:\n  - {metavariable: X, kind: not_regex, regex: "^pass"}')
    assert run(nrx, "f(password)\nf(user)") == [2]


def test_where_concat_in_js_and_php() -> None:
    js = _rule(
        'pattern: "db.query($Q)"\nwhere:\n  - {metavariable: Q, kind: fstring_or_concat}',
        "[javascript]",
    )  # noqa: E501
    code = "db.query(`select ${id}`)\ndb.query('select ' + id)\ndb.query('select 1')\ndb.query(q)\n"
    assert run(js, code, "javascript") == [1, 2]
    php = _rule(
        'pattern: "DB::raw($Q)"\nwhere:\n  - {metavariable: Q, kind: fstring_or_concat}', "[php]"
    )  # noqa: E501
    code = "<?php\nDB::raw(\"select $id\");\nDB::raw('select ' . $id);\nDB::raw('select 1');\nDB::raw($q);\n"  # noqa: E501
    assert run(php, code, "php") == [2, 3]


def test_rule_compile_error_names_rule_and_language() -> None:
    rule = _rule('pattern: "eval($X"')
    with pytest.raises(PatternError, match=r"t-rule.*python"):
        compile_rule(rule)


def test_unknown_language_for_run_returns_nothing() -> None:
    rule = _rule('pattern: "eval($X)"')
    crule = compile_rule(rule)
    pf = _parse("javascript", "eval(a)")
    assert run_rule(crule, "javascript", FileIndex(pf.tree)) == []


def test_pathological_pattern_is_bounded() -> None:
    pattern = "f(" + ", ".join(["..."] * 8) + ", x)"
    code = "f(" + ", ".join(["a"] * 60) + ")"
    assert count("python", pattern, code) == 0  # completes quickly, no exponential blow-up


TS_WRAPPERS = [
    ("createClient($U, process.env.$V)", "createClient(u, process.env.KEY!)", 1),
    ("createClient($U, process.env.$V)", "createClient(u, process.env.KEY as string)", 1),
    ("createClient($U, process.env.$V)", "createClient(u, (process.env.KEY))", 1),
    ("createClient($U, process.env.$V)", "createClient(u, process.env.KEY satisfies string)", 1),
    ("createClient($U, process.env.$V)", "createClient(u, process.env['KEY'])", 0),
    ("createClient($U, process.env.$V)", "createClient(u, other.env.KEY!)", 0),
    ("$X.from($T).select(...)", "(await supabase.from('a')).select('*')", 1),
    ("eval($X)", "eval(<any>input)", 1),
]


@pytest.mark.parametrize(("pattern", "code", "expected"), TS_WRAPPERS)
def test_typescript_wrappers_are_transparent(pattern: str, code: str, expected: int) -> None:
    assert count("typescript", pattern, code) == expected
