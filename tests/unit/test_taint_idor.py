"""Tier-B IDOR via taint + ownership guards (WP-5.8)."""

from __future__ import annotations

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.taint import ProjectAnalysis
from vulnfab.core.taintspec import TaintSpec

JS = TaintSpec.from_rule(
    ["field req.params"],
    ["call *.findByPk arg0"],
    [],
    [],
    ["field req.user", "field req.session"],
)


def run(code: str):
    pf = parse_file(SourceFile("t.js", "javascript", code, "0" * 64))
    return ProjectAnalysis([lower_file(pf)], JS).run()


def test_unguarded_fetch_by_key_is_reported() -> None:
    assert run("function h(req){ return Doc.findByPk(req.params.id); }\n")


def test_guard_in_same_function_suppresses() -> None:
    code = "function h(req){ const u = req.user.id; return Doc.findByPk(req.params.id); }\n"
    assert not run(code)


def test_guard_in_caller_suppresses_callee_sink() -> None:
    code = (
        "function load(id){ return Doc.findByPk(id); }\n"
        "function h(req){ const u = req.session.uid; return load(req.params.id); }\n"
    )
    assert not run(code)


def test_guard_in_callee_suppresses() -> None:
    code = (
        "function load(id, req){ const u = req.user; return Doc.findByPk(id); }\n"
        "function h(req){ return load(req.params.id, req); }\n"
    )
    assert not run(code)


def test_unguarded_chain_reported_in_callee() -> None:
    code = (
        "function load(id){ return Doc.findByPk(id); }\n"
        "function h(req){ return load(req.params.id); }\n"
    )
    (hit,) = run(code)
    assert hit.line == 1


def test_no_guards_means_never_suppressed() -> None:
    spec = TaintSpec.from_rule(["field req.params"], ["call *.findByPk arg0"], [], [])
    pf = parse_file(
        SourceFile(
            "t.js",
            "javascript",
            "function h(req){ req.user; Doc.findByPk(req.params.id); }",
            "0" * 64,
        )
    )
    assert ProjectAnalysis([lower_file(pf)], spec).run()
