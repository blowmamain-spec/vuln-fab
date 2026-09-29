import time

import pytest

from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import (
    Deadline,
    ParseFailure,
    TimeoutExceeded,
    enclosing_symbol,
    node_text,
    parse_file,
    walk,
)


def _sf(text: str, language: str = "python", path: str = "a.py") -> SourceFile:
    return SourceFile(path=path, language=language, text=text, sha256="0" * 64)


def test_parse_each_language() -> None:
    for lang, code in [
        ("python", "x = 1\n"),
        ("javascript", "let x = 1;\n"),
        ("typescript", "let x: number = 1;\n"),
        ("tsx", "const a = <div/>;\n"),
        ("php", "<?php echo 1;\n"),
    ]:
        pf = parse_file(_sf(code, lang))
        assert pf.tree is not None and not pf.has_syntax_errors, lang


def test_syntax_error_is_flagged_not_fatal() -> None:
    pf = parse_file(_sf("def broken(:\n"))
    assert pf.has_syntax_errors


def test_unsupported_language() -> None:
    with pytest.raises(ParseFailure) as info:
        parse_file(_sf("select 1;", "sql", "a.sql"))
    assert info.value.reason == "unsupported_language"


def test_pathologically_deep_ast_is_rejected_without_recursion_error() -> None:
    deep = "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n"
    with pytest.raises(ParseFailure) as info:
        parse_file(_sf(deep))
    assert "ast_too_deep" in info.value.detail


def test_walk_is_iterative_on_deep_input() -> None:
    deep = "x = " + "(" * 3000 + "1" + ")" * 3000 + "\n"
    pf = parse_file(_sf(deep), max_depth=10_000)
    assert sum(1 for _ in walk(pf.tree.root_node)) > 3000


def test_deadline_stops_walk() -> None:
    pf = parse_file(_sf("\n".join(f"x{i} = {i}" for i in range(2000))))
    deadline = Deadline(0.0)
    time.sleep(0.001)
    with pytest.raises(TimeoutExceeded):
        list(walk(pf.tree.root_node, deadline))


def test_enclosing_symbol() -> None:
    code = "class A:\n    def m(self):\n        return eval('1')\n"
    pf = parse_file(_sf(code))
    call = next(n for n in walk(pf.tree.root_node) if n.type == "call")
    assert node_text(call, pf.source) == "eval('1')"
    assert enclosing_symbol(call, pf.source) == "A.m"
