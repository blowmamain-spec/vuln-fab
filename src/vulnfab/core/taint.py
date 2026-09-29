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

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from vulnfab.core.models import TraceStep
from vulnfab.core.modindex import ModuleIndex
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
    Const,
    Field,
    FunctionIR,
    Index,
    Instr,
    Loop,
    ModuleIR,
    Operand,
    Return,
    Var,
)

MAX_TRACE = 14
MAX_FUNCTION_STEPS = 200_000  # instruction visits for one function analysis
MAX_PROJECT_STEPS = 5_000_000  # instruction visits for one rule over the whole project
PROJECT_SECONDS = 60.0
MAX_LOOP_ROUNDS = 3

# Calls that keep data flowing without being a modelling gap (string plumbing).
DEFAULT_PROPAGATORS = (
    "*.format", "*.join", "*.replace", "*.strip", "*.lstrip", "*.rstrip", "*.lower", "*.upper",
    "*.split", "*.encode", "*.decode", "*.concat", "*.slice", "*.substring", "*.toString",
    "*.trim", "*.toLowerCase", "*.toUpperCase", "*.append", "*.items", "*.values",
    "str", "String", "unicode", "sprintf", "vsprintf", "implode", "trim", "strtolower",
    "strtoupper", "str_replace", "substr", "json_decode", "json.loads", "JSON.parse",
    "path.join", "path.resolve", "path.normalize", "os.path.join", "os.path.normpath",
    "base64_decode", "urldecode", "rawurldecode", "stripslashes", "array_merge", "dict", "list",
)  # fmt: skip


@dataclass(frozen=True)
class Taint:
    trace: tuple[TraceStep, ...]
    hops: int = 0
    escaped: bool = False  # passed through an escaper and still inside a quoted literal

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

# Marks a path as validated: reads of it (or of what lies below) are clean even when the path
# matches a source such as ``$_GET``.
CLEAN = Taint(())


@dataclass
class TaintHit:
    line: int
    trace: tuple[TraceStep, ...]
    hops: int
    function: str
    sink: str
    file: str = ""


@dataclass(frozen=True)
class SinkRef:
    """A sink inside a function reached by one of its parameters."""

    line: int
    sink: str
    function: str
    file: str
    trace: tuple[TraceStep, ...]  # steps after the parameter marker, ending with the sink step
    hops: int


@dataclass
class Summary:
    to_return: frozenset[int] = frozenset()
    to_sink: dict[int, list[SinkRef]] = field(default_factory=dict)
    source_return: Taint | None = None  # the function returns data from a real source


@dataclass(frozen=True)
class Resolved:
    fn: FunctionIR
    offset: int  # number of leading parameters (self/cls) not passed positionally
    summary: Summary


Resolver = Callable[[str, FunctionIR], Resolved | None]
MARKER = "\0param:"


class BudgetExceeded(Exception):
    pass


class Budget:
    """Shared work/time limits so pathological code cannot stall a scan (WP-5.6)."""

    def __init__(
        self,
        max_steps: int = MAX_PROJECT_STEPS,
        seconds: float | None = PROJECT_SECONDS,
        function_steps: int = MAX_FUNCTION_STEPS,
    ) -> None:
        self.max_steps = max_steps
        self.function_steps = function_steps
        self.steps = 0
        self.exhausted = False
        self._end = None if seconds is None else time.monotonic() + seconds

    def tick(self, local: int) -> None:
        self.steps += 1
        if self.exhausted or self.steps > self.max_steps:
            self.exhausted = True
            raise BudgetExceeded
        if local > self.function_steps:
            raise BudgetExceeded
        if self.steps % 2048 == 0 and self._end is not None and time.monotonic() > self._end:
            self.exhausted = True
            raise BudgetExceeded


@dataclass
class _Ctx:
    spec: TaintSpec
    file: str
    hits: list[TaintHit] = field(default_factory=list)
    seen: set[tuple[int, str]] = field(default_factory=set)
    resolver: Resolver | None = None
    seeds: dict[str, Taint] = field(default_factory=dict)
    returns: list[Taint] = field(default_factory=list)
    budget: Budget | None = None
    steps: int = 0
    guarded: bool = False


def _merge(a: State, b: State) -> State:
    out = dict(a)
    for key, value in b.items():
        current = out.get(key)
        if current is None or value.hops < current.hops:
            out[key] = value
    return out


def _receiver_is_source(spec: TaintSpec, callee: str) -> bool:
    """``request.args.get`` reads from the source ``request.args`` (the method name is excluded)."""
    receiver = callee.rsplit(".", 1)[0] if "." in callee else None
    return receiver is not None and matches_path(spec.sources, "field", receiver)


def _writes(body: tuple[Instr, ...], path: str) -> bool:
    for instr in _walk(body):
        dst = getattr(instr, "dst", None)
        if dst is not None:
            target = access_path(dst)
            if target == path or (target or "").startswith(path + "."):
                return True
    return False


def _terminates(body: tuple[Instr, ...]) -> bool:
    return bool(body) and isinstance(body[-1], Return)


class FunctionAnalyzer:
    def __init__(self, ctx: _Ctx, fn: FunctionIR) -> None:
        self.ctx = ctx
        self.fn = fn
        self.defs: dict[str, Instr] = {}
        self.templates: dict[str, str] = {}  # static text of built strings (\0 = dynamic part)

    # --- operands ---------------------------------------------------------------------------

    def read(self, op: Operand, state: State, line: int) -> Taint | None:
        spec = self.ctx.spec
        path = access_path(op)
        if path is not None:
            for prefix in reversed(path_prefixes(path)):  # most specific first
                if prefix in state:
                    value = state[prefix]
                    return None if value is CLEAN else value
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
        state: State = dict(self.ctx.seeds)
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
        dst = getattr(instr, "dst", None)
        if isinstance(dst, Var) and isinstance(instr, (Call, Concat, Assign)):
            self.defs[dst.name] = instr
        if self.ctx.budget is not None:
            self.ctx.steps += 1
            self.ctx.budget.tick(self.ctx.steps)
        if isinstance(instr, Assign):
            taint = self.read(instr.src, state, instr.line)
            if taint is not None and isinstance(instr.dst, (Var, Field)):
                taint = taint.step(
                    self.ctx.file, instr.line, "propagate", f"{access_path(instr.dst)} = …"
                )  # noqa: E501
            self.assign_sink(instr, taint)
            self.write(instr.dst, taint, state)
        elif isinstance(instr, Concat):
            self.write(instr.dst, self.concat(instr, state), state)
        elif isinstance(instr, Call):
            self.call(instr, state)
        elif isinstance(instr, Branch):
            state = self.branch(instr, state)
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
            if instr.value is not None:
                taint = self.read(instr.value, state, instr.line)
                if taint is not None:
                    self.ctx.returns.append(taint)
        return state

    def concat(self, instr: Concat, state: State) -> Taint | None:
        """Taint of a built string. An escaped value only stays escaped inside a quoted literal."""
        found: list[Taint] = []
        prefix = ""
        for part in instr.parts:
            if isinstance(part, Const):
                prefix += str(part.value)
                continue
            if isinstance(part, Var) and part.name in self.templates:
                prefix += self.templates[part.name]
            taint = self.read(part, state, instr.line)
            if taint is None:
                continue
            if (
                taint.escaped
                and prefix.replace("\0", "").strip()
                and not (prefix.count("'") % 2 == 1 or prefix.count('"') % 2 == 1)
            ):
                taint = replace(
                    taint, escaped=False
                )  # e.g. `WHERE id = $escaped` (numeric context)
            found.append(taint)
        self.templates[instr.dst.name] = "".join(
            str(p.value)
            if isinstance(p, Const)
            else self.templates.get(p.name, "\0")
            if isinstance(p, Var)
            else "\0"
            for p in instr.parts
        )
        if not found:
            return None
        live = [t for t in found if not t.escaped] or found
        return min(live, key=lambda t: t.hops)

    def branch(self, instr: Branch, state: State) -> State:
        validated = self.validated_operands(instr)
        if not validated:
            then = self.block(instr.then, dict(state))
            other = self.block(instr.other, dict(state))
            return _merge(then, other)
        # A validation check clears its operands inside both arms. After the branch they stay
        # clean only if one arm cannot continue (early return / throw); otherwise the check
        # guarded nothing we can see, so the original taint is restored.
        cleared = dict(state)
        for target in validated:
            path = access_path(target)
            if path is not None:
                self.write(target, None, cleared)
                cleared[path] = CLEAN
        a = self.block(instr.then, dict(cleared))
        b = self.block(instr.other, dict(cleared))
        a_ends, b_ends = _terminates(instr.then), _terminates(instr.other)
        if a_ends and not b_ends:
            return b
        if b_ends and not a_ends:
            return a
        merged = _merge(a, b)
        if not (a_ends and b_ends):
            for target in validated:
                path = access_path(target)
                repaired = path is not None and (
                    _writes(instr.then, path) or _writes(instr.other, path)
                )  # "if not valid(x): x = default" leaves x clean afterwards
                if path is not None and not repaired and merged.get(path) is CLEAN:
                    if path in state:
                        merged[path] = state[path]
                    else:
                        del merged[path]
        return merged

    def validated_operands(self, branch: Branch) -> list[Operand]:
        """Operands of validator calls (rule ``validators``) inside the branch condition."""
        validators = self.ctx.spec.validators
        if not validators or branch.cond is None:
            return []
        found: list[Operand] = []
        seen: set[str] = set()

        def visit(op: Operand, depth: int) -> None:
            if not isinstance(op, Var) or op.name in seen or depth > 5:
                return
            seen.add(op.name)
            defn = self.defs.get(op.name)
            if isinstance(defn, Call):
                if any(m.kind == "call" and m.matches_name(defn.callee) for m in validators):
                    found.extend(defn.args)
                    found.extend(v for _, v in defn.kwargs)
                    if defn.recv is not None:
                        found.append(defn.recv)
                    if "." in defn.callee:
                        found.append(Var(defn.callee.rsplit(".", 1)[0]))
                for arg in defn.args:
                    visit(arg, depth + 1)
            elif isinstance(defn, Concat):
                for part in defn.parts:
                    visit(part, depth + 1)
            elif isinstance(defn, Assign):
                visit(defn.src, depth + 1)

        visit(branch.cond, 0)
        return found

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

        resolved = self.ctx.resolver(callee, self.fn) if self.ctx.resolver else None
        result: Taint | None
        if any(m.kind == "call" and m.matches_name(callee) for m in spec.sanitizers):
            result = None
        elif any(m.kind == "call" and m.matches_name(callee) for m in spec.escapers):
            inputs = [t for t in [*in_args, *in_kwargs.values(), in_recv] if t is not None]
            result = replace(min(inputs, key=lambda t: t.hops), escaped=True) if inputs else None
        elif any(m.kind == "call" and m.matches_name(callee) for m in spec.sources) or matches_path(
            spec.sources, "field", callee
        ):
            result = Taint((TraceStep(self.ctx.file, instr.line, "source", f"{callee}(…)"),))
        elif resolved is not None:
            result = self.apply_summary(instr, resolved, in_args, in_kwargs)
        else:
            if callee.endswith(".get") and in_args:
                # mapping lookup: the *key* does not taint the result, the container/default do
                container = callee[: -len(".get")]
                lookup = in_recv or self.read(Var(container), state, instr.line)
                rest = [*in_args[1:], *in_kwargs.values()]
                inputs = [t for t in [lookup, *rest] if t is not None]
            else:
                inputs = [t for t in [*in_args, *in_kwargs.values(), in_recv] if t is not None]
            if not inputs:
                result = None
            else:
                first = min(inputs, key=lambda t: t.hops)
                known = (
                    any(m.kind == "call" and m.matches_name(callee) for m in spec.propagators)
                    or any(_glob(callee, g) for g in DEFAULT_PROPAGATORS)
                    or callee.endswith(".get")
                )
                result = first if known else first.hop()
                result = result.step(self.ctx.file, instr.line, "call", f"via {callee}(…)")
        self.write(instr.dst, result, state)

    def apply_summary(
        self,
        instr: Call,
        resolved: Resolved,
        in_args: list[Taint | None],
        in_kwargs: dict[str, Taint | None],
    ) -> Taint | None:
        by_index: dict[int, Taint] = {}
        for i, t in enumerate(in_args):
            if t is not None:
                by_index[i + resolved.offset] = t
        for name, t in in_kwargs.items():
            if t is not None and name in resolved.fn.params:
                by_index[resolved.fn.params.index(name)] = t
        summary = resolved.summary
        for idx, taint in by_index.items():
            entered = taint.step(
                self.ctx.file, instr.line, "call", f"passed to {resolved.fn.qualname}(…)"
            )
            for ref in summary.to_sink.get(idx, []):
                self.report_ref(entered, ref)
        candidates = [
            t.step(self.ctx.file, instr.line, "return", f"returned by {resolved.fn.qualname}(…)")
            for idx, t in by_index.items()
            if idx in summary.to_return
        ]
        if summary.source_return is not None:
            candidates.append(summary.source_return)
        return min(candidates, key=lambda t: t.hops) if candidates else None

    def report_ref(self, entered: Taint, ref: SinkRef) -> None:
        if self.ctx.guarded or entered.escaped:
            return
        key = (ref.line, ref.sink + "@" + ref.file)
        if key in self.ctx.seen:
            return
        self.ctx.seen.add(key)
        trace = (*entered.trace, *ref.trace)
        self.ctx.hits.append(
            TaintHit(ref.line, trace, entered.hops + ref.hops, ref.function, ref.sink, ref.file)
        )

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
        if self.ctx.guarded or taint.escaped:
            return
        key = (line, sink)
        if key in self.ctx.seen:
            return
        self.ctx.seen.add(key)
        trace = taint.step(self.ctx.file, line, "sink", sink).trace
        self.ctx.hits.append(
            TaintHit(line, trace, taint.hops, self.fn.qualname, sink, self.ctx.file)
        )


def _glob(name: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(name, pattern)


def analyze_function(
    fn: FunctionIR, spec: TaintSpec, file: str, resolver: Resolver | None = None
) -> list[TaintHit]:
    ctx = _Ctx(spec, file, resolver=resolver)
    FunctionAnalyzer(ctx, fn).run()
    return ctx.hits


MAX_SUMMARY_PARAMS = 8
MAX_SUMMARY_DEPTH = 8
_BOUND = ("self.", "cls.", "this.", "$this.")


@dataclass(frozen=True)
class FunctionFacts:
    paths: frozenset[str]  # every variable/field access path read or written
    callees: frozenset[str]
    last_names: frozenset[str]  # final segment of each callee name


FactCache = dict[tuple[str, str], FunctionFacts]  # (file, qualname) -> facts


def function_facts(fn: FunctionIR, cache: FactCache) -> FunctionFacts:
    """Rule-independent summary of a function body; ``cache`` may be shared across rules."""
    key = (fn.file, fn.qualname)
    cached = cache.get(key)
    if cached is not None:
        return cached
    paths: set[str] = set()
    callees: set[str] = set()

    def add(op: Operand) -> None:
        path = access_path(op)
        if path is not None:
            paths.add(path)

    for instr in _walk(fn.body):
        if isinstance(instr, Assign):
            add(instr.src)
            add(instr.dst)
        elif isinstance(instr, Concat):
            for part in instr.parts:
                add(part)
        elif isinstance(instr, Return) and instr.value is not None:
            add(instr.value)
        elif isinstance(instr, Call):
            callees.add(instr.callee)
            for arg in instr.args:
                add(arg)
            for _, value in instr.kwargs:
                add(value)
            if instr.recv is not None:
                add(instr.recv)
    facts = FunctionFacts(
        frozenset(paths),
        frozenset(callees),
        frozenset(c.replace("::", ".").split(".")[-1] for c in callees),
    )
    cache[key] = facts
    return facts


class ProjectAnalysis:
    """Taint over a set of modules: summaries are shared across files through import resolution."""

    def __init__(
        self,
        modules: list[ModuleIR],
        spec: TaintSpec,
        budget: Budget | None = None,
        facts: FactCache | None = None,
    ) -> None:
        self.spec = spec
        self.facts: FactCache = facts if facts is not None else {}
        self.budget = budget or Budget()
        self.truncated: list[tuple[str, str, int]] = []  # (file, function, line)
        self._path_memo: dict[str, bool] = {}
        self._callee_memo: dict[str, bool] = {}
        self._guarded: dict[tuple[str, str], bool] = {}
        self.stack: list[tuple[str, str]] = []
        self.index = ModuleIndex({m.file: m.language for m in modules})
        self.modules: dict[str, ModuleAnalysis] = {}
        for m in modules:
            self.modules[m.file] = ModuleAnalysis(m, spec, self)

    def guarded(self, fn: FunctionIR) -> bool:
        """Does ``fn`` reference any ownership evidence (rule ``guards``)?"""
        guards = self.spec.guards
        if not guards:
            return False
        key = (fn.file, fn.qualname)
        found = self._guarded.get(key)
        if found is None:
            facts = function_facts(fn, self.facts)
            found = (
                any(m.kind == "param" and m.matches_name(p) for m in guards for p in fn.params)
                or any(
                    matches_path(guards, "field", p) or matches_path(guards, "var", p)
                    for p in facts.paths
                )
                or any(
                    any(m.kind == "call" and m.matches_name(c) for m in guards)
                    or matches_path(guards, "field", c)
                    for c in facts.callees
                )
            )
            self._guarded[key] = found
        return found

    def _has_source(self, fn: FunctionIR, facts: FunctionFacts) -> bool:
        spec = self.spec
        if any(m.kind == "param" and m.matches_name(p) for m in spec.sources for p in fn.params):
            return True
        for path in facts.paths:
            hit = self._path_memo.get(path)
            if hit is None:
                hit = matches_path(spec.sources, "field", path) or matches_path(
                    spec.sources, "var", path
                )
                self._path_memo[path] = hit
            if hit:
                return True
        for callee in facts.callees:
            hit = self._callee_memo.get(callee)
            if hit is None:
                hit = any(
                    m.kind == "call" and m.matches_name(callee) for m in spec.sources
                ) or _receiver_is_source(spec, callee)
                self._callee_memo[callee] = hit
            if hit:
                return True
        return False

    def entries(self) -> set[tuple[str, str]]:
        """Functions whose own analysis can produce hits: they read a source directly or call
        (by name) a function that returns/hides one. Everything else is only analysed lazily
        when an entry calls it."""
        facts: dict[tuple[str, str], tuple[bool, frozenset[str]]] = {}
        for ma in self.modules.values():
            for fn in ma.module.functions:
                ff = function_facts(fn, self.facts)
                facts[(ma.module.file, fn.qualname)] = (
                    self._has_source(fn, ff),
                    ff.last_names,
                )
        names: dict[str, list[tuple[str, str]]] = {}
        for ma in self.modules.values():
            for fn in ma.module.functions:
                names.setdefault(fn.name, []).append((ma.module.file, fn.qualname))
        entry = {k for k, (direct, _) in facts.items() if direct}
        entry_names = {q.split(".")[-1] for _, q in entry}
        changed = True
        while changed:
            changed = False
            for key, (_, callees) in facts.items():
                if key not in entry and callees & entry_names:
                    entry.add(key)
                    entry_names.add(key[1].split(".")[-1])
                    changed = True
        return entry

    def run(self) -> list[TaintHit]:
        out: list[TaintHit] = []
        seen: set[tuple[str, int, str]] = set()
        entry = self.entries()
        for ma in self.modules.values():
            for h in ma.run(entry):
                if (h.file, h.line, h.sink) not in seen:
                    seen.add((h.file, h.line, h.sink))
                    out.append(h)
        return sorted(out, key=lambda h: (h.file, h.line, h.sink))


class ModuleAnalysis:
    """Per-file taint: function summaries applied at call sites, same file or imported."""

    def __init__(
        self, module: ModuleIR, spec: TaintSpec, project: ProjectAnalysis | None = None
    ) -> None:
        self.module = module
        self.spec = spec
        self.project = project or ProjectAnalysis([], spec)
        self.summaries: dict[str, Summary] = {}
        self.hits: dict[str, list[TaintHit]] = {}
        self._by_name: dict[str, list[FunctionIR]] = {}
        for fn in module.functions:
            self._by_name.setdefault(fn.name, []).append(fn)
        self.exported: dict[str, FunctionIR] = {}
        self._scan_commonjs()

    # --- CommonJS: require() imports and exports.x = function -------------------------------

    def _scan_commonjs(self) -> None:
        if self.module.language not in ("javascript", "typescript", "tsx"):
            return
        required: dict[str, str] = {}
        for fn in self.module.functions:
            for instr in _walk(fn.body):
                if (
                    isinstance(instr, Call)
                    and instr.callee == "require"
                    and len(instr.args) == 1
                    and isinstance(instr.args[0], Const)
                    and isinstance(instr.args[0].value, str)
                ):
                    required[instr.dst.name] = instr.args[0].value
                elif isinstance(instr, Assign):
                    src, dst = instr.src, access_path(instr.dst)
                    if isinstance(src, Var) and src.name in required and isinstance(instr.dst, Var):
                        self.module.imports.setdefault(instr.dst.name, (required[src.name], "*"))
                    elif (
                        isinstance(src, Field)
                        and isinstance(src.base, Var)
                        and src.base.name in required
                        and isinstance(instr.dst, Var)
                    ):
                        self.module.imports.setdefault(
                            instr.dst.name, (required[src.base.name], src.name)
                        )
                    elif (
                        dst
                        and isinstance(src, Var)
                        and dst.startswith(("exports.", "module.exports."))
                    ):
                        target = self.module.function(src.name)
                        if target is not None:
                            self.exported[dst.rsplit(".", 1)[1]] = target

    # --- resolution -------------------------------------------------------------------------

    def resolve(self, callee: str, caller: FunctionIR) -> Resolved | None:
        found = self._resolve_local(callee, caller) or self._resolve_import(callee)
        if found is None:
            return None
        ma, target, offset = found
        if (ma.module.file, target.qualname) in self.project.stack:
            return None
        if len(self.project.stack) >= MAX_SUMMARY_DEPTH:
            return None
        return Resolved(target, offset, ma.summary(target))

    def _resolve_local(
        self, callee: str, caller: FunctionIR
    ) -> tuple[ModuleAnalysis, FunctionIR, int] | None:
        target: FunctionIR | None = None
        offset = 0
        bound = next((p for p in _BOUND if callee.startswith(p)), None)
        if bound is not None and caller.class_name:
            name = callee[len(bound) :]
            target = next(
                (
                    f
                    for f in self._by_name.get(name, [])
                    if f.class_name == caller.class_name and "." not in name
                ),
                None,
            )
            if target is not None and target.params[:1] in (("self",), ("cls",)):
                offset = 1
        elif "." not in callee:
            cands = [f for f in self._by_name.get(callee, []) if f.class_name is None]
            target = cands[0] if len(cands) == 1 else None
        else:
            target = self.module.function(callee.replace("::", "."))
        return (self, target, offset) if target is not None else None

    def _resolve_import(self, callee: str) -> tuple[ModuleAnalysis, FunctionIR, int] | None:
        head, _, rest = callee.partition(".")
        imp = self.module.imports.get(head)
        if imp is None:
            return None
        module, name = imp
        path = self.project.index.resolve(self.module.file, module)
        ma = self.project.modules.get(path) if path else None
        if ma is None:
            return None
        if name == "*":
            func = callee[len(module) + 1 :] if callee.startswith(module + ".") else rest
            if not func or "." in func:
                return None
            target = ma.lookup(func)
        elif not rest:
            target = ma.lookup(head if name == "default" else name)
        else:
            target = ma.module.function(f"{name}.{rest}")
        return (ma, target, 0) if target is not None else None

    def lookup(self, name: str) -> FunctionIR | None:
        if name in self.exported:
            return self.exported[name]
        cands = [f for f in self._by_name.get(name, []) if f.class_name is None]
        return cands[0] if len(cands) == 1 else None

    # --- summaries --------------------------------------------------------------------------

    def summary(self, fn: FunctionIR) -> Summary:
        cached = self.summaries.get(fn.qualname)
        if cached is not None:
            return cached
        file = self.module.file
        self.project.stack.append((file, fn.qualname))
        try:
            try:
                guarded = self.project.guarded(fn)
                base = _Ctx(
                    self.spec,
                    file,
                    resolver=self.resolve,
                    budget=self.project.budget,
                    guarded=guarded,
                )
                FunctionAnalyzer(base, fn).run()
                summary = Summary()
                returned = [t for t in base.returns if not t.trace[0].detail.startswith(MARKER)]
                if returned:
                    summary.source_return = min(returned, key=lambda t: t.hops)
                to_return: set[int] = set()
                for idx, param in enumerate(fn.params[:MAX_SUMMARY_PARAMS]):
                    marker = Taint((TraceStep(file, fn.line, "source", MARKER + param),))
                    ctx = _Ctx(
                        self.spec,
                        file,
                        resolver=self.resolve,
                        seeds={param: marker},
                        budget=self.project.budget,
                        guarded=guarded,
                    )
                    FunctionAnalyzer(ctx, fn).run()
                    if any(t.trace[0].detail == MARKER + param for t in ctx.returns):
                        to_return.add(idx)
                    for hit in ctx.hits:
                        if hit.trace and hit.trace[0].detail == MARKER + param:
                            summary.to_sink.setdefault(idx, []).append(
                                SinkRef(
                                    hit.line,
                                    hit.sink,
                                    hit.function,
                                    hit.file,
                                    hit.trace[1:],
                                    hit.hops,
                                )
                            )
                summary.to_return = frozenset(to_return)
                self.hits[fn.qualname] = [
                    h for h in base.hits if not (h.trace and h.trace[0].detail.startswith(MARKER))
                ]
            except (BudgetExceeded, RecursionError):
                self.project.truncated.append((file, fn.qualname, fn.line))
                summary = Summary()
                self.hits[fn.qualname] = []
        finally:
            self.project.stack.pop()
        self.summaries[fn.qualname] = summary
        return summary

    def run(self, entry: set[tuple[str, str]] | None = None) -> list[TaintHit]:
        for fn in self.module.functions:
            if entry is None or (self.module.file, fn.qualname) in entry:
                self.summary(fn)
        out: list[TaintHit] = []
        seen: set[tuple[str, int, str]] = set()
        for hits in self.hits.values():
            for h in hits:
                if (h.file, h.line, h.sink) not in seen:
                    seen.add((h.file, h.line, h.sink))
                    out.append(h)
        return sorted(out, key=lambda h: (h.file, h.line, h.sink))


def _walk(body: tuple[Instr, ...]):  # type: ignore[no-untyped-def]
    for instr in body:
        yield instr
        if isinstance(instr, Branch):
            yield from _walk(instr.then)
            yield from _walk(instr.other)
        elif isinstance(instr, Loop):
            yield from _walk(instr.body)
