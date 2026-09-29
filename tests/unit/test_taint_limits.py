"""Robustness limits (WP-5.6): pathological code finishes fast and reports truncation."""

from __future__ import annotations

import time

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.core.taint import Budget, ProjectAnalysis
from vulnfab.core.taintspec import TaintSpec

PY = TaintSpec.from_rule(["field request.args"], ["call os.system"], ["call int"], [])


def analysis(code: str, budget: Budget | None = None) -> ProjectAnalysis:
    pf = parse_file(SourceFile("t.py", "python", code, "0" * 64))
    a = ProjectAnalysis([lower_file(pf)], PY, budget)
    a.hits = a.run()  # type: ignore[attr-defined]
    return a


def nested_loops(depth: int) -> str:
    lines = ["def f(xs):", "    q = request.args['a']"]
    for i in range(depth):
        lines.append("    " * (i + 1) + f"for i{i} in xs:")
    lines.append("    " * (depth + 1) + "q = q + 'x'")
    lines.append("    os.system(q)")
    return "\n".join(lines) + "\n"


def test_deeply_nested_loops_finish_quickly() -> None:
    start = time.monotonic()
    a = analysis(nested_loops(12))
    assert time.monotonic() - start < 20
    assert a.hits or a.truncated  # either analysed or reported as truncated


def test_function_step_limit_reports_truncation() -> None:
    a = analysis(nested_loops(6), Budget(function_steps=50))
    assert a.truncated and a.truncated[0][1] == "f"
    assert a.hits == []


def test_project_step_limit_truncates_rest() -> None:
    code = "\n".join(f"def f{i}():\n    os.system(request.args['a'])\n" for i in range(50))
    a = analysis(code, Budget(max_steps=30))
    assert len(a.truncated) > 0
    assert len(a.hits) < 50


def test_many_branches() -> None:
    body = "\n".join(f"    if c{i}:\n        q = q + '{i}'" for i in range(300))
    code = f"def f():\n    q = request.args['a']\n{body}\n    os.system(q)\n"
    a = analysis(code)
    assert len(a.hits) == 1 and not a.truncated


def test_long_call_chain_does_not_recurse_forever() -> None:
    defs = [f"def f{i}(x):\n    return f{i + 1}(x)\n" for i in range(300)]
    code = (
        "\n".join(defs) + "def f300(x):\n    os.system(x)\n\ndef v():\n    f0(request.args['a'])\n"
    )
    start = time.monotonic()
    analysis(code)
    assert time.monotonic() - start < 20
