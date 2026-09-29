"""Taint specification DSL (sources, sinks, sanitizers, propagators) matched against TIR.

Grammar of one entry (whitespace separated)::

    call   <glob> [arg0|arg1|..|args|recv|kw:<name>]   # call by callee name; arg = which input
    field  <glob>                                       # access path such as req.query.id
    var    <glob>                                       # variable name (e.g. PHP superglobal _GET)
    param  <glob>                                       # function parameter name
    assign <glob>                                       # assignment target path (el.innerHTML)

Globs use ``fnmatch`` (``*`` = anything). Callee names come from the front-ends: ``os.system``,
``cursor.execute``, ``DB::raw``, ``new Foo``, and ``?.execute`` when the receiver is not a plain
dotted name. Access-path entries also match any *prefix* of a longer path (``req.query`` matches
``req.query.id``).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from vulnfab.core.tir import Const, Field, Index, Operand, Var

KINDS = ("call", "field", "var", "param", "assign")
_ARG_RE = re.compile(r"^(?:arg\d+|args|recv|any|kw:[A-Za-z_][\w]*)$")


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class Matcher:
    kind: str
    glob: str
    arg: str | None = None  # only for call sinks

    def matches_name(self, name: str) -> bool:
        return fnmatch.fnmatchcase(name, self.glob)


def parse_matcher(text: str, *, sink: bool = False) -> Matcher:
    parts = text.split()
    if len(parts) < 2 or parts[0] not in KINDS:
        raise SpecError(f"expected '<{'|'.join(KINDS)}> <glob> [arg]', got {text!r}")
    kind, rest = parts[0], parts[1:]
    glob, rest = rest[0], rest[1:]
    if glob == "new" and rest:  # constructor callee names contain a space: "new Function"
        glob, rest = f"new {rest[0]}", rest[1:]
    if len(rest) > 1:
        raise SpecError(f"too many words in {text!r}")
    arg = rest[0] if rest else None
    if arg is not None:
        if kind != "call" or not sink:
            raise SpecError(f"an argument selector is only valid on 'call' sinks: {text!r}")
        if not _ARG_RE.match(arg):
            raise SpecError(f"bad argument selector {arg!r} (arg0, args, recv, kw:name)")
    if sink and kind == "call" and arg is None:
        arg = "args"
    return Matcher(kind, glob, arg)


@dataclass(frozen=True)
class TaintSpec:
    sources: tuple[Matcher, ...]
    sinks: tuple[Matcher, ...]
    sanitizers: tuple[Matcher, ...]
    propagators: tuple[Matcher, ...]
    guards: tuple[Matcher, ...] = ()  # ownership evidence: a function that uses one is not reported

    @classmethod
    def from_rule(
        cls,
        sources: list[str],
        sinks: list[str],
        sanitizers: list[str],
        propagators: list[str],
        guards: list[str] | None = None,
    ) -> TaintSpec:
        return cls(
            tuple(parse_matcher(s) for s in sources),
            tuple(parse_matcher(s, sink=True) for s in sinks),
            tuple(parse_matcher(s) for s in sanitizers),
            tuple(parse_matcher(s) for s in propagators),
            tuple(parse_matcher(s) for s in guards or []),
        )


def access_path(op: Operand) -> str | None:
    """Dotted path of a variable/field chain; indexes do not extend it. ``None`` if not a path."""
    if isinstance(op, Var):
        return op.name
    if isinstance(op, Field):
        base = access_path(op.base)
        return f"{base}.{op.name}" if base is not None else None
    if isinstance(op, Index):
        return access_path(op.base)
    return None


def path_prefixes(path: str) -> list[str]:
    parts = path.split(".")
    return [".".join(parts[: i + 1]) for i in range(len(parts))]


def matches_path(matchers: tuple[Matcher, ...], kind: str, path: str) -> bool:
    return any(
        m.kind == kind and any(m.matches_name(p) for p in path_prefixes(path)) for m in matchers
    )


def is_constant(op: Operand) -> bool:
    return isinstance(op, Const)
