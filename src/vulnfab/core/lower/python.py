"""Python -> TIR."""

from __future__ import annotations

import re

from tree_sitter import Node

from vulnfab.core.lower.base import Lowerer
from vulnfab.core.tir import (
    Branch,
    Concat,
    Const,
    Field,
    Index,
    Loop,
    ModuleIR,
    Operand,
    Return,
    Unknown,
    Var,
)

_STRING_PREFIX = re.compile(r"^[rRbBuUfF]{0,2}")


class PythonLowerer(Lowerer):
    language = "python"

    def lower(self) -> ModuleIR:
        body = self.block(self.root)
        self.add_function("<module>", (), body, self.root)
        self.module.functions.insert(0, self.module.functions.pop())
        return self.module

    # --- statements -------------------------------------------------------------------------

    def s_expression_statement(self, node: Node) -> None:
        for child in self.named(node):
            if child.type == "assignment":
                self._assignment(child)
            elif child.type == "augmented_assignment":
                self.s_augmented_assignment(child)
            else:
                self.expr(child)

    def s_function_definition(self, node: Node, decorators: tuple[str, ...] = ()) -> None:
        name = self.text(node.child_by_field_name("name"))
        params = self._params(node.child_by_field_name("parameters"))
        body = self.block(node.child_by_field_name("body"))
        self.add_function(name, params, body, node, decorators)

    def s_decorated_definition(self, node: Node) -> None:
        decorators = tuple(
            self.text(c).lstrip("@").strip() for c in node.children if c.type == "decorator"
        )
        definition = node.child_by_field_name("definition")
        if definition is None:
            return
        if definition.type == "function_definition":
            self.s_function_definition(definition, decorators)
        else:
            self.stmt(definition)

    def s_class_definition(self, node: Node) -> None:
        saved = self._class
        self._class = self.text(node.child_by_field_name("name"))
        try:
            for child in self.named(node.child_by_field_name("body") or node):
                self.stmt(child)
        finally:
            self._class = saved

    def s_return_statement(self, node: Node) -> None:
        kids = self.named(node)
        self.emit(Return(self.expr(kids[0]) if kids else None, self.line(node)))

    def s_assignment(self, node: Node) -> None:
        self._assignment(node)

    def _assignment(self, node: Node) -> Operand:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        value = (
            self._assignment(right)
            if right is not None and right.type == "assignment"
            else self.expr(right)
        )  # noqa: E501
        self._bind(left, value, node)
        return value

    def _bind(self, target: Node | None, value: Operand, at: Node) -> None:
        if target is None:
            return
        if target.type in ("pattern_list", "tuple_pattern", "list_pattern", "expression_list"):
            for i, child in enumerate(self.named(target)):
                self._bind(child, Index(value, Const(i)), at)
        elif target.type in ("list_splat_pattern", "tuple_pattern"):
            for child in self.named(target):
                self._bind(child, value, at)
        else:
            self.assign_to(self._target(target), value, at)

    def _target(self, node: Node) -> Operand:
        if node.type == "identifier":
            return Var(self.text(node))
        if node.type == "attribute":
            return Field(
                self.expr(node.child_by_field_name("object")),
                self.text(node.child_by_field_name("attribute")),
            )  # noqa: E501
        if node.type == "subscript":
            return Index(self.expr(node.child_by_field_name("value")), self._subscript_key(node))
        self.unhandled(node)
        return Unknown(node.type)

    def _subscript_key(self, node: Node) -> Operand:
        keys = node.children_by_field_name("subscript")
        return self.expr(keys[0]) if keys else Unknown("subscript")

    def s_augmented_assignment(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = self.expr(node.child_by_field_name("right"))
        if left is None:
            return
        target = self._target(left)
        dst = self.temp()
        self.emit(Concat(dst, (target, right), self.line(node)))
        self.assign_to(target, dst, node)

    def s_if_statement(self, node: Node) -> None:
        cond = self.expr(node.child_by_field_name("condition"))
        then = self.block(node.child_by_field_name("consequence"))
        other: tuple = ()  # type: ignore[type-arg]
        alternatives = node.children_by_field_name("alternative")
        if alternatives:
            other = self._elif_chain(alternatives)
        self.emit(Branch(then, other, self.line(node), cond))

    def _elif_chain(self, alternatives: list[Node]) -> tuple:  # type: ignore[type-arg]
        head, rest = alternatives[0], alternatives[1:]
        if head.type == "else_clause":
            return self.block(head.child_by_field_name("body"))

        def run() -> None:
            cond = self.expr(head.child_by_field_name("condition"))
            then = self.block(head.child_by_field_name("consequence"))
            other = self._elif_chain(rest) if rest else ()
            self.emit(Branch(then, other, self.line(head), cond))

        return self.capture(run)

    def s_for_statement(self, node: Node) -> None:
        iterable = self.expr(node.child_by_field_name("right"))
        left = node.child_by_field_name("left")
        line = self.line(node)

        def run() -> None:
            self._bind(left, Index(iterable, Unknown("iter")), node)
            for child in self.named(node.child_by_field_name("body") or node):
                self.stmt(child)

        self.emit(Loop(self.capture(run), line))

    def s_while_statement(self, node: Node) -> None:
        def run() -> None:
            self.expr(node.child_by_field_name("condition"))
            for child in self.named(node.child_by_field_name("body") or node):
                self.stmt(child)

        self.emit(Loop(self.capture(run), self.line(node)))

    def s_try_statement(self, node: Node) -> None:
        for child in self.named(node.child_by_field_name("body") or node):
            self.stmt(child)
        handlers = [c for c in node.children if c.type in ("except_clause", "except_group_clause")]
        for handler in handlers:
            self.emit(Branch(self.block(handler), (), self.line(handler)))
        for c in node.children:
            if c.type in ("else_clause", "finally_clause"):
                for child in self.named(c):
                    self.stmt(child)

    def s_with_statement(self, node: Node) -> None:
        for clause in node.children:
            if clause.type == "with_clause":
                for item in self.named(clause):
                    value = item.child_by_field_name("value") if item.type == "with_item" else item
                    if value is not None and value.type == "as_pattern":
                        kids = self.named(value)
                        inner = self.expr(kids[0])
                        alias = value.child_by_field_name("alias")
                        if alias is not None and kids:
                            self._bind(
                                self.named(alias)[0] if alias.named_child_count else alias,
                                inner,
                                node,
                            )  # noqa: E501
                    else:
                        self.expr(value)
        for child in self.named(node.child_by_field_name("body") or node):
            self.stmt(child)

    def s_import_statement(self, node: Node) -> None:
        for child in self.named(node):
            if child.type == "dotted_name":
                name = self.text(child)
                self.module.imports[name.split(".")[0]] = (name, "*")
            elif child.type == "aliased_import":
                name = self.text(child.child_by_field_name("name"))
                alias = self.text(child.child_by_field_name("alias"))
                self.module.imports[alias] = (name, "*")

    def s_import_from_statement(self, node: Node) -> None:
        module = self.text(node.child_by_field_name("module_name"))
        for child in node.children_by_field_name("name"):
            if child.type == "aliased_import":
                name = self.text(child.child_by_field_name("name"))
                alias = self.text(child.child_by_field_name("alias"))
            else:
                name = alias = self.text(child)
            self.module.imports[alias] = (module, name)

    def s_assert_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.expr(child)

    s_delete_statement = s_assert_statement

    def s_raise_statement(self, node: Node) -> None:
        self.s_assert_statement(node)
        self.emit(Return(None, self.line(node)))  # control does not continue

    def _params(self, node: Node | None) -> tuple[str, ...]:
        names: list[str] = []
        for child in self.named(node) if node is not None else []:
            target = child
            if child.type in ("typed_parameter", "list_splat_pattern", "dictionary_splat_pattern"):
                inner = [c for c in self.named(child) if c.type == "identifier"]
                target = inner[0] if inner else child
            elif child.type in ("default_parameter", "typed_default_parameter"):
                target = child.child_by_field_name("name") or child
            if target.type == "identifier":
                names.append(self.text(target))
        return tuple(names)

    # --- expressions ------------------------------------------------------------------------

    def x_identifier(self, node: Node) -> Operand:
        return Var(self.text(node))

    def x_attribute(self, node: Node) -> Operand:
        return Field(
            self.expr(node.child_by_field_name("object")),
            self.text(node.child_by_field_name("attribute")),
        )  # noqa: E501

    def x_subscript(self, node: Node) -> Operand:
        return Index(self.expr(node.child_by_field_name("value")), self._subscript_key(node))

    def x_call(self, node: Node) -> Operand:
        fn = node.child_by_field_name("function")
        args: list[Operand] = []
        kwargs: list[tuple[str, Operand]] = []
        arguments = node.child_by_field_name("arguments")
        for child in self.named(arguments) if arguments is not None else []:
            if child.type == "keyword_argument":
                kwargs.append(
                    (
                        self.text(child.child_by_field_name("name")),
                        self.expr(child.child_by_field_name("value")),
                    )
                )  # noqa: E501
            elif child.type in ("list_splat", "dictionary_splat"):
                args.extend(self.expr(c) for c in self.named(child))
            else:
                args.append(self.expr(child))
        recv: Operand | None = None
        callee = "?"
        if fn is not None and fn.type == "identifier":
            callee = self.text(fn)
        elif fn is not None and fn.type == "attribute":
            obj = fn.child_by_field_name("object")
            method = self.text(fn.child_by_field_name("attribute"))
            dotted = self._dotted(obj)
            recv = self.expr(obj)
            callee = f"{dotted}.{method}" if dotted else f"?.{method}"
        elif fn is not None:
            recv = self.expr(fn)
        return self.call(node, callee, recv, args, kwargs)

    def _dotted(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            return self.text(node)
        if node.type == "attribute":
            base = self._dotted(node.child_by_field_name("object"))
            return f"{base}.{self.text(node.child_by_field_name('attribute'))}" if base else None
        return None

    def x_string(self, node: Node) -> Operand:
        interpolations = [c for c in node.children if c.type == "interpolation"]
        if interpolations:
            parts: list[Operand] = []
            for child in node.children:  # keep the literal text: quote context matters to escapers
                if child.type == "interpolation":
                    parts.append(self.expr(child.child_by_field_name("expression")))
                elif child.type in ("string_content", "escape_sequence"):
                    parts.append(Const(self.text(child)))
            return self._concat(parts, node)
        text = self.text(node)
        prefix = _STRING_PREFIX.match(text)
        body = text[len(prefix.group(0)) if prefix else 0 :]
        for quote in ('"""', "'''", '"', "'"):
            if body.startswith(quote) and body.endswith(quote) and len(body) >= 2 * len(quote):
                return Const(body[len(quote) : -len(quote)])
        return Const(text)

    def _concat(self, parts: list[Operand], at: Node) -> Operand:
        if not parts:
            return Const("")
        dst = self.temp()
        self.emit(Concat(dst, tuple(parts), self.line(at)))
        return dst

    def x_concatenated_string(self, node: Node) -> Operand:
        return self._concat([self.expr(c) for c in self.named(node)], node)

    def x_integer(self, node: Node) -> Operand:
        try:
            return Const(int(self.text(node).replace("_", ""), 0))
        except ValueError:
            return Const(self.text(node))

    def x_float(self, node: Node) -> Operand:
        try:
            return Const(float(self.text(node).replace("_", "")))
        except ValueError:
            return Const(self.text(node))

    def x_true(self, node: Node) -> Operand:
        return Const(True)

    def x_false(self, node: Node) -> Operand:
        return Const(False)

    def x_none(self, node: Node) -> Operand:
        return Const(None)

    def x_parenthesized_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("empty")

    def x_await(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("await")

    def x_binary_operator(self, node: Node) -> Operand:
        return self._concat(
            [
                self.expr(node.child_by_field_name("left")),
                self.expr(node.child_by_field_name("right")),
            ],
            node,
        )  # noqa: E501

    x_boolean_operator = x_binary_operator

    def x_comparison_operator(self, node: Node) -> Operand:
        return self._concat([self.expr(c) for c in self.named(node)], node)

    def x_not_operator(self, node: Node) -> Operand:
        return self.expr(node.child_by_field_name("argument"))

    x_unary_operator = x_not_operator

    def x_conditional_expression(self, node: Node) -> Operand:
        kids = self.named(node)  # [value, condition, alternative]
        return self._concat([self.expr(k) for k in kids], node)

    def x_list(self, node: Node) -> Operand:
        return self._concat([self.expr(c) for c in self.named(node)], node)

    x_tuple = x_list
    x_set = x_list
    x_expression_list = x_list

    def x_dictionary(self, node: Node) -> Operand:
        parts: list[Operand] = []
        for pair in self.named(node):
            if pair.type == "pair":
                parts.append(self.expr(pair.child_by_field_name("value")))
            else:
                parts.append(self.expr(pair))
        return self._concat(parts, node)

    def x_list_comprehension(self, node: Node) -> Operand:
        return self._concat([self.expr(node.child_by_field_name("body"))], node)

    x_generator_expression = x_list_comprehension
    x_set_comprehension = x_list_comprehension
    x_dictionary_comprehension = x_list_comprehension

    def x_lambda(self, node: Node) -> Operand:
        self.unhandled(node)
        return Unknown("lambda")

    def x_ellipsis(self, node: Node) -> Operand:
        return Const(None)

    def x_named_expression(self, node: Node) -> Operand:
        value = self.expr(node.child_by_field_name("value"))
        name = node.child_by_field_name("name")
        if name is not None:
            self.assign_to(Var(self.text(name)), value, node)
        return value

    def x_keyword_argument(self, node: Node) -> Operand:
        return self.expr(node.child_by_field_name("value"))

    def x_yield(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("yield")


__all__ = ["PythonLowerer"]
