"""Is a value built only from constants and pure computations? (used to demote heuristics)

A pattern rule such as "eval() of a non-literal" cannot see where the argument comes from. When the
whole value is provably made of constants and pure calls (arithmetic, ``Math.random()``, ``str()``),
it is not attacker-controlled, and the finding is only a code smell.
"""

from __future__ import annotations

import fnmatch

from vulnfab.core.tir import (
    Assign,
    Branch,
    Call,
    Concat,
    Const,
    Field,
    FunctionIR,
    Index,
    Instr,
    Loop,
    Operand,
    Var,
)

PURE_CALLS = (
    "Math.*", "Number", "parseInt", "parseFloat", "String", "Boolean", "Date.now", "Symbol",
    "*.toString", "*.toFixed", "*.toUpperCase", "*.toLowerCase", "*.trim", "*.padStart",
    "int", "float", "str", "bool", "len", "abs", "round", "min", "max", "sum", "range",
    "random.*", "uuid.*", "time.time", "datetime.now", "datetime.datetime.now",
    "intval", "floatval", "strval", "count", "rand", "mt_rand", "time", "date", "uniqid",
    "crypto.randomInt", "crypto.randomUUID", "t*.toString", "t*.toFixed",
)  # fmt: skip


def _walk(body: tuple[Instr, ...]):  # type: ignore[no-untyped-def]
    for instr in body:
        yield instr
        if isinstance(instr, Branch):
            yield from _walk(instr.then)
            yield from _walk(instr.other)
        elif isinstance(instr, Loop):
            yield from _walk(instr.body)


def _pure_call(callee: str) -> bool:
    return any(fnmatch.fnmatchcase(callee, pattern) for pattern in PURE_CALLS)


def _benign(op: Operand, pure: set[str]) -> bool:
    if isinstance(op, Const):
        return True
    if isinstance(op, Var):
        return op.name in pure
    if isinstance(op, Field) and isinstance(op.base, Var):
        return op.base.name in ("Math", "Number")  # Math.PI, Number.MAX_VALUE
    if isinstance(op, Index):
        return _benign(op.base, pure) and _benign(op.key, pure)
    return False


def pure_locals(fn: FunctionIR) -> set[str]:
    """Variables whose every assignment is benign (greatest fixed point; params never are)."""
    assigns: dict[str, list[Instr]] = {}
    for instr in _walk(fn.body):
        dst = getattr(instr, "dst", None)
        if isinstance(dst, Var) and isinstance(instr, (Assign, Concat, Call)):
            assigns.setdefault(dst.name, []).append(instr)
    pure = {name for name in assigns if name not in fn.params}
    assigned = set(assigns)
    changed = True
    while changed:
        changed = False
        for name in list(pure):
            if not all(_instr_benign(i, pure, assigned) for i in assigns[name]):
                pure.discard(name)
                changed = True
    return pure


def _instr_benign(instr: Instr, pure: set[str], assigned: set[str]) -> bool:
    if isinstance(instr, Assign):
        return _benign(instr.src, pure)
    if isinstance(instr, Concat):
        return all(_benign(p, pure) for p in instr.parts)
    if isinstance(instr, Call):
        if not _pure_call(instr.callee):
            return False
        if not all(_benign(o, pure) for o in [*instr.args, *(v for _, v in instr.kwargs)]):
            return False
        recv = instr.recv
        # a receiver that is a local must itself be benign; module-like globals (Math, random) are
        # fine because the callee already matched the pure-call list
        return not (isinstance(recv, Var) and recv.name in assigned and recv.name not in pure)
    return False


def line_is_benign(fn: FunctionIR, line: int) -> bool:
    """Do all calls with arguments on ``line`` receive only benign values?"""
    pure = pure_locals(fn)
    seen = False
    for instr in _walk(fn.body):
        if isinstance(instr, Call) and instr.line == line and (instr.args or instr.kwargs):
            if _pure_call(instr.callee):
                continue
            seen = True
            operands = [*instr.args, *(v for _, v in instr.kwargs)]
            if not all(_benign(o, pure) for o in operands):
                return False
    return seen
