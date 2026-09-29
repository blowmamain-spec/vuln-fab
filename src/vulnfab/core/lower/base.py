"""Shared machinery for lowering tree-sitter trees into TIR."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tree_sitter import Node

from vulnfab.core.parsing import LineIndex, node_text
from vulnfab.core.tir import (
    Assign,
    Call,
    Concat,
    FunctionIR,
    Instr,
    ModuleIR,
    Operand,
    Unknown,
    Var,
)

MAX_DEPTH = 120  # recursion guard; the AST depth limit is larger than Python's stack allows


class Lowerer:
    """Base class: temp allocation, instruction emission, node dispatch with a depth guard."""

    language = ""

    def __init__(self, file: str, source: bytes, root: Node) -> None:
        self.file = file
        self.src = source
        self.root = root
        self.lines = LineIndex(source)
        self.module = ModuleIR(file=file, language=self.language)
        self._code: list[Instr] = []
        self._tmp = 0
        self._depth = 0
        self._class: str | None = None

    # --- helpers ------------------------------------------------------------------------

    def text(self, node: Node | None) -> str:
        return node_text(node, self.src) if node is not None else ""

    def line(self, node: Node) -> int:
        return self.lines.line(node.start_byte)

    def temp(self) -> Var:
        self._tmp += 1
        return Var(f"t{self._tmp}")

    def emit(self, instr: Instr) -> None:
        self._code.append(instr)

    def capture(self, fn: Callable[[], None]) -> tuple[Instr, ...]:
        """Run ``fn`` collecting the instructions it emits into a separate block."""
        saved, self._code = self._code, []
        try:
            fn()
            return tuple(self._code)
        finally:
            self._code = saved

    def guard(self, node: Node) -> bool:
        return self._depth > MAX_DEPTH

    def unhandled(self, node: Node) -> None:
        self.module.unhandled[node.type] += 1

    def named(self, node: Node) -> list[Node]:
        return [c for c in node.children if c.is_named and c.type != "comment"]

    def concat_of(self, nodes: list[Node], at: Node) -> Operand:
        parts = tuple(self.expr(n) for n in nodes)
        if not parts:
            return Unknown(at.type)
        if len(parts) == 1:
            return parts[0]
        dst = self.temp()
        self.emit(Concat(dst, parts, self.line(at)))
        return dst

    def approximate(self, node: Node) -> Operand:
        """Unmodelled expression: children flow into the result (sound over-approximation)."""
        self.unhandled(node)
        return self.concat_of(self.named(node), node)

    def call(
        self,
        node: Node,
        callee: str,
        recv: Operand | None,
        args: list[Operand],
        kwargs: list[tuple[str, Operand]],
    ) -> Var:
        dst = self.temp()
        self.emit(Call(dst, callee, recv, tuple(args), tuple(kwargs), self.line(node)))
        return dst

    def expr(self, node: Node | None) -> Operand:
        if node is None:
            return Unknown("missing")
        if self.guard(node):
            self.unhandled(node)
            return Unknown("too deep")
        handler: Any = getattr(self, f"x_{node.type}", None)
        self._depth += 1
        try:
            return handler(node) if handler else self.approximate(node)
        finally:
            self._depth -= 1

    def stmt(self, node: Node) -> None:
        if self.guard(node):
            self.unhandled(node)
            return
        handler: Any = getattr(self, f"s_{node.type}", None)
        self._depth += 1
        try:
            if handler:
                handler(node)
            elif node.is_named and node.type not in self.IGNORED:
                # unknown statement: evaluate children so calls inside are not lost
                self.unhandled(node)
                for child in self.named(node):
                    self.stmt(child) if child.type.endswith(
                        ("statement", "definition", "declaration")
                    ) else self.expr(child)  # noqa: E501
        finally:
            self._depth -= 1

    IGNORED: frozenset[str] = frozenset(
        {"comment", "pass_statement", "break_statement", "continue_statement"}
    )  # noqa: E501

    def block(self, node: Node | None) -> tuple[Instr, ...]:
        if node is None:
            return ()

        def run() -> None:
            for child in self.named(node):
                self.stmt(child)

        return self.capture(run)

    # --- function collection ----------------------------------------------------------------

    def add_function(
        self,
        name: str,
        params: tuple[str, ...],
        body: tuple[Instr, ...],
        node: Node,
        decorators: tuple[str, ...] = (),
    ) -> None:
        qual = f"{self._class}.{name}" if self._class else name
        first, last = self.lines.lines(node)
        self.module.functions.append(
            FunctionIR(name, qual, params, body, self.file, first, last, decorators, self._class)
        )

    def lower(self) -> ModuleIR:
        raise NotImplementedError

    def assign_to(self, target: Operand, value: Operand, at: Node) -> None:
        self.emit(Assign(target, value, self.line(at)))
