"""TIR: the small, language-neutral three-address IR the taint engine works on (WP-5.1).

Every language front-end (core/lower/*) flattens expressions into temporaries so that data flow
is explicit: ``x = f(g(a) + "s")`` becomes ``t1 = call g(a)``, ``t2 = concat(t1, 's')``,
``t3 = call f(t2)``, ``x = t3``. Unsupported syntax is over-approximated (children flow into the
result) and counted, never silently dropped.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# --- operands ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Var:
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Const:
    value: str | int | float | bool | None

    def __str__(self) -> str:
        return repr(self.value)


@dataclass(frozen=True)
class Field:
    base: Operand
    name: str

    def __str__(self) -> str:
        return f"{self.base}.{self.name}"


@dataclass(frozen=True)
class Index:
    base: Operand
    key: Operand

    def __str__(self) -> str:
        return f"{self.base}[{self.key}]"


@dataclass(frozen=True)
class Unknown:
    reason: str

    def __str__(self) -> str:
        return f"?({self.reason})"


Operand = Var | Const | Field | Index | Unknown

# --- instructions --------------------------------------------------------------------------


@dataclass(frozen=True)
class Assign:
    dst: Operand  # Var, Field or Index
    src: Operand
    line: int


@dataclass(frozen=True)
class Call:
    dst: Var
    callee: str  # dotted name ("os.system", "DB::raw", "new Foo") or "?.method" for chains
    recv: Operand | None
    args: tuple[Operand, ...]
    kwargs: tuple[tuple[str, Operand], ...]
    line: int


@dataclass(frozen=True)
class Concat:
    """Any value built from several operands: concatenation, interpolation, containers."""

    dst: Var
    parts: tuple[Operand, ...]
    line: int


@dataclass(frozen=True)
class Return:
    value: Operand | None
    line: int


@dataclass(frozen=True)
class Branch:
    then: tuple[Instr, ...]
    other: tuple[Instr, ...]
    line: int
    cond: Operand | None = None  # the tested value (lets analyses spot validation checks)


@dataclass(frozen=True)
class Loop:
    body: tuple[Instr, ...]
    line: int


Instr = Assign | Call | Concat | Return | Branch | Loop


@dataclass
class FunctionIR:
    name: str
    qualname: str
    params: tuple[str, ...]
    body: tuple[Instr, ...]
    file: str
    line: int
    end_line: int
    decorators: tuple[str, ...] = ()
    class_name: str | None = None


@dataclass
class ModuleIR:
    file: str
    language: str
    functions: list[FunctionIR] = field(default_factory=list)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (module, name)
    unhandled: Counter[str] = field(default_factory=Counter)  # node types approximated

    def function(self, qualname: str) -> FunctionIR | None:
        return next((f for f in self.functions if f.qualname == qualname), None)


# --- printing (used by `vulnfab ir` and by the golden tests) ---------------------------------


def format_instr(instr: Instr, indent: int = 0) -> list[str]:
    pad = "  " * indent
    match instr:
        case Assign(dst, src, line):
            return [f"{pad}L{line}: {dst} = {src}"]
        case Call(dst, callee, recv, args, kwargs, line):
            shown = [str(a) for a in args] + [f"{k}={v}" for k, v in kwargs]
            target = (
                f"{recv}.{callee.removeprefix('?.')}"
                if recv is not None and callee.startswith("?.")
                else callee
            )  # noqa: E501
            return [f"{pad}L{line}: {dst} = call {target}({', '.join(shown)})"]
        case Concat(dst, parts, line):
            return [f"{pad}L{line}: {dst} = concat({', '.join(str(p) for p in parts)})"]
        case Return(value, line):
            return [f"{pad}L{line}: return{'' if value is None else f' {value}'}"]
        case Branch(then, other, line):
            out = [f"{pad}L{line}: branch"]
            out.append(f"{pad}  then:")
            out.extend(line for i in then for line in format_instr(i, indent + 2))
            if other:
                out.append(f"{pad}  else:")
                out.extend(line for i in other for line in format_instr(i, indent + 2))
            return out
        case Loop(body, line):
            return [
                f"{pad}L{line}: loop",
                *(line for i in body for line in format_instr(i, indent + 1)),
            ]
    return [f"{pad}?"]


def format_module(module: ModuleIR) -> str:
    out: list[str] = []
    for fn in module.functions:
        params = ", ".join(fn.params)
        deco = f" @{','.join(fn.decorators)}" if fn.decorators else ""
        out.append(f"def {fn.qualname}({params}){deco}  [L{fn.line}-{fn.end_line}]")
        for instr in fn.body:
            out.extend(format_instr(instr, 1))
    if module.unhandled:
        approx = ", ".join(f"{k}×{v}" for k, v in sorted(module.unhandled.items()))
        out.append(f"# approximated: {approx}")
    return "\n".join(out) + "\n"
