"""Intra-procedural taint analysis on TIR (WP-5.3).

A value is *tainted* if data from a source may reach it. Propagation:
- assignment and string building (concat) carry taint;
- a call to a sanitizer returns a clean value;
- a call to a known propagator carries taint from its inputs;
- a call to an *unknown* function also carries taint but counts one ``unresolved hop``, which
  later lowers the finding's confidence (docs/spec.md section 4);
- branches merge by union; loops run to a small fixpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from vulnfab.core.models import TraceStep
from vulnfab.core.taintspec import (
    Matcher,
    TaintSpec,
    access_path,
    matches_path,
    path_prefixes,
)
from vulnfab.core.tir import (
    Assign,
    Branch,
    Call,
    Concat,
    Field,
    FunctionIR,
    Index,
    Instr,
    Loop,
    Operand,
    Return,
    Var,
)

MAX_TRACE = 14
MAX_LOOP_ROUNDS = 3

# Calls that keep data flowing without being a modelling gap (string plumbing).
DEFAULT_PROPAGATORS = (
    "*.format", "*.join", "*.replace", "*.strip", "*.lstrip", "*.rstrip", "*.lower", "*.upper",
    "*.split", "*.encode", "*.decode", "*.concat", "*.slice", "*.substring", "*.toString",
    "*.trim", "*.toLowerCase", "*.toUpperCase", "*.get", "*.append", "*.items", "*.values",
    "str", "String", "unicode", "sprintf", "vsprintf", "implode", "trim", "strtolower",
    "strtoupper", "str_replace", "substr", "json_decode", "json.loads", "JSON.parse",
    "base64_decode", "urldecode", "rawurldecode", "stripslashes", "array_merge", "dict", "list",
)  # fmt: skip


@dataclass(frozen=True)
class Taint:
    trace: tuple[TraceStep, ...]
    hops: int = 0

    def step(self, file: str, line: int, kind: str, detail: str) -> Taint:
        new = TraceStep(file, line, kind, detail)  # type: ignore[arg-type]
        if self.trace and self.trace[-1] == new:
            return self
        trace = (*self.trace, new)
        if len(trace) > MAX_TRACE:  # keep the source and the tail
            trace = (
                trace[0],
                TraceStep(file, line, "propagate", "..."),
                *trace[-(MAX_TRACE - 2) :],
            )
        return replace(self, trace=trace)

    def hop(self) -> Taint:
        return replace(self, hops=self.hops + 1)


State = dict[str, Taint]


@dataclass
class TaintHit:
    line: int
    trace: tuple[TraceStep, ...]
    hops: int
    function: str
    sink: str


@dataclass
class _Ctx:
    spec: TaintSpec
    file: str
    hits: list[TaintHit] = field(default_factory=list)
    seen: set[tuple[int, str]] = field(default_factory=set)


def _merge(a: State, b: State) -> State:
    out = dict(a)
    for key, value in b.items():
        current = out.get(key)
        if current is None or value.hops < current.hops:
            out[key] = value
    return out


class FunctionAnalyzer:
    def __init__(self, ctx: _Ctx, fn: FunctionIR) -> None:
        self.ctx = ctx
        self.fn = fn

    # --- operands ---------------------------------------------------------------------------

    def read(self, op: Operand, state: State, line: int) -> Taint | None:
        spec = self.ctx.spec
        path = access_path(op)
        if path is not None:
            for prefix in reversed(path_prefixes(path)):  # most specific first
                if prefix in state:
                    return state[prefix]
            if matches_path(spec.sources, "field", path) or matches_path(spec.sources, "var", path):
                return Taint((TraceStep(self.ctx.file, line, "source", path),))
        if isinstance(op, Index):
            return self.read(op.base, state, line)
        if isinstance(op, Field):
            return self.read(op.base, state, line)
        return None

    def write(self, dst: Operand, taint: Taint | None, state: State) -> None:
        path = access_path(dst)
        if path is None:
            return
        if isinstance(dst, Index):  # weak update: the container becomes (more) tainted
            if taint is not None and path not in state:
                state[path] = taint
            return
        for key in [k for k in state if k == path or k.startswith(path + ".")]:
            del state[key]
        if taint is not None:
            state[path] = taint

    # --- execution --------------------------------------------------------------------------

    def run(self) -> None:
        state: State = {}
        for param in self.fn.params:
            if any(m.kind == "param" and m.matches_name(param) for m in self.ctx.spec.sources):
                state[param] = Taint(
                    (TraceStep(self.ctx.file, self.fn.line, "source", f"parameter {param}"),)
                )
        self.block(self.fn.body, state)

    def block(self, body: tuple[Instr, ...], state: State) -> State:
        for instr in body:
            state = self.instr(instr, state)
        return state

    def instr(self, instr: Instr, state: State) -> State:
        if isinstance(instr, Assign):
            taint = self.read(instr.src, state, instr.line)
            if taint is not None and isinstance(instr.dst, (Var, Field)):
                taint = taint.step(
                    self.ctx.file, instr.line, "propagate", f"{access_path(instr.dst)} = …"
                )  # noqa: E501
            self.assign_sink(instr, taint)
            self.write(instr.dst, taint, state)
        elif isinstance(instr, Concat):
            taints = [t for p in instr.parts if (t := self.read(p, state, instr.line)) is not None]
            self.write(instr.dst, taints[0] if taints else None, state)
        elif isinstance(instr, Call):
            self.call(instr, state)
        elif isinstance(instr, Branch):
            a = self.block(instr.then, dict(state))
            b = self.block(instr.other, dict(state))
            state = _merge(a, b)
        elif isinstance(instr, Loop):
            current = state
            for _ in range(MAX_LOOP_ROUNDS):
                after = self.block(instr.body, dict(current))
                merged = _merge(current, after)
                if set(merged) == set(current):
                    current = merged
                    break
                current = merged
            state = current
        elif isinstance(instr, Return):
            pass
        return state

    def assign_sink(self, instr: Assign, taint: Taint | None) -> None:
        path = access_path(instr.dst)
        if taint is None or path is None:
            return
        for m in self.ctx.spec.sinks:
            if m.kind == "assign" and m.matches_name(path):
                self.report(instr.line, taint, f"assignment to {path}")

    def call(self, instr: Call, state: State) -> None:
        spec = self.ctx.spec
        callee = instr.callee
        in_args = [self.read(a, state, instr.line) for a in instr.args]
        in_kwargs = {k: self.read(v, state, instr.line) for k, v in instr.kwargs}
        in_recv = self.read(instr.recv, state, instr.line) if instr.recv is not None else None

        for sink in spec.sinks:
            if sink.kind == "call" and sink.matches_name(callee):
                hit = self._sink_taint(sink, in_args, in_kwargs, in_recv)
                if hit is not None:
                    self.report(instr.line, hit, f"call to {callee}")

        result: Taint | None
        if any(m.kind == "call" and m.matches_name(callee) for m in spec.sanitizers):
            result = None
        elif any(m.kind == "call" and m.matches_name(callee) for m in spec.sources):
            result = Taint((TraceStep(self.ctx.file, instr.line, "source", f"{callee}(…)"),))
        else:
            inputs = [t for t in [*in_args, *in_kwargs.values(), in_recv] if t is not None]
            if not inputs:
                result = None
            else:
                first = min(inputs, key=lambda t: t.hops)
                known = any(
                    m.kind == "call" and m.matches_name(callee) for m in spec.propagators
                ) or any(_glob(callee, g) for g in DEFAULT_PROPAGATORS)
                result = first if known else first.hop()
                result = result.step(self.ctx.file, instr.line, "call", f"via {callee}(…)")
        self.write(instr.dst, result, state)

    @staticmethod
    def _sink_taint(
        sink: Matcher, args: list[Taint | None], kwargs: dict[str, Taint | None], recv: Taint | None
    ) -> Taint | None:
        sel = sink.arg or "args"
        if sel == "recv":
            return recv
        if sel == "args":
            return next((t for t in args if t is not None), None)
        if sel == "any":
            return next((t for t in [*args, *kwargs.values(), recv] if t is not None), None)
        if sel.startswith("kw:"):
            return kwargs.get(sel[3:])
        index = int(sel[3:])
        return args[index] if index < len(args) else None

    def report(self, line: int, taint: Taint, sink: str) -> None:
        key = (line, sink)
        if key in self.ctx.seen:
            return
        self.ctx.seen.add(key)
        trace = taint.step(self.ctx.file, line, "sink", sink).trace
        self.ctx.hits.append(TaintHit(line, trace, taint.hops, self.fn.qualname, sink))


def _glob(name: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(name, pattern)


def analyze_function(fn: FunctionIR, spec: TaintSpec, file: str) -> list[TaintHit]:
    ctx = _Ctx(spec, file)
    FunctionAnalyzer(ctx, fn).run()
    return ctx.hits
