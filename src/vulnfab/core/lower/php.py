"""PHP -> TIR."""

from __future__ import annotations

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


class PhpLowerer(Lowerer):
    language = "php"

    def lower(self) -> ModuleIR:
        body = self.block(self.root)
        self.add_function("<module>", (), body, self.root)
        self.module.functions.insert(0, self.module.functions.pop())
        return self.module

    IGNORED = Lowerer.IGNORED | frozenset(
        {"php_tag", "text", "text_interpolation", "namespace_definition", "empty_statement",
         "namespace_use_declaration", "comment", "declare_statement"}
    )  # fmt: skip

    # --- helpers --------------------------------------------------------------------------

    def _concat(self, parts: list[Operand], at: Node) -> Operand:
        if not parts:
            return Const("")
        dst = self.temp()
        self.emit(Concat(dst, tuple(parts), self.line(at)))
        return dst

    def _name(self, node: Node | None) -> str:
        return self.text(node).lstrip("\\") if node is not None else "?"

    def _var_name(self, node: Node) -> str:
        return self.text(node).lstrip("$")

    def _function(self, node: Node, name: str | None = None) -> Operand:
        label = name or f"<anon@{self.line(node)}>"
        params = self._params(node.child_by_field_name("parameters"))
        body = node.child_by_field_name("body")

        def run() -> None:
            if body is None:
                return
            if body.type == "compound_statement":
                for child in self.named(body):
                    self.stmt(child)
            else:
                self.emit(Return(self.expr(body), self.line(body)))

        self.add_function(label, params, self.capture(run), node)
        return Var(label)

    def _params(self, node: Node | None) -> tuple[str, ...]:
        names: list[str] = []
        for param in self.named(node) if node is not None else []:
            var = param.child_by_field_name("name")
            if var is not None and var.type == "variable_name":
                names.append(self._var_name(var))
        return tuple(names)

    def _bind(self, target: Node | None, value: Operand, at: Node) -> None:
        if target is None:
            return
        t = target.type
        if t == "variable_name":
            self.assign_to(Var(self._var_name(target)), value, at)
        elif t == "member_access_expression":
            self.assign_to(
                Field(
                    self.expr(target.child_by_field_name("object")),
                    self._name(target.child_by_field_name("name")),
                ),
                value,
                at,
            )  # noqa: E501
        elif t == "subscript_expression":
            kids = self.named(target)
            key = self.expr(kids[1]) if len(kids) > 1 else Unknown("append")
            self.assign_to(Index(self.expr(kids[0]), key), value, at)
        elif t == "list_literal" or t == "array_creation_expression":
            for i, child in enumerate(self.named(target)):
                inner = self.named(child)
                self._bind(inner[-1] if inner else child, Index(value, Const(i)), at)
        else:
            self.unhandled(target)

    # --- statements -----------------------------------------------------------------------

    def s_expression_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.expr(child)

    def s_compound_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.stmt(child)

    def s_function_definition(self, node: Node) -> None:
        self._function(node, self._name(node.child_by_field_name("name")))

    def s_class_declaration(self, node: Node) -> None:
        saved = self._class
        self._class = self._name(node.child_by_field_name("name"))
        try:
            body = node.child_by_field_name("body")
            for member in self.named(body) if body is not None else []:
                if member.type == "method_declaration":
                    self._function(member, self._name(member.child_by_field_name("name")))
        finally:
            self._class = saved

    s_trait_declaration = s_class_declaration
    s_interface_declaration = s_class_declaration

    def s_echo_statement(self, node: Node) -> None:
        args = [self.expr(c) for c in self.named(node)]
        self.call(node, "echo", None, args, [])

    def s_return_statement(self, node: Node) -> None:
        kids = self.named(node)
        self.emit(Return(self.expr(kids[0]) if kids else None, self.line(node)))

    def s_if_statement(self, node: Node) -> None:
        cond = self.expr(node.child_by_field_name("condition"))
        then = self._arm(node.child_by_field_name("body"))
        other = ()
        alternatives = node.children_by_field_name("alternative")
        if alternatives:
            other = self._alt_chain(alternatives)
        self.emit(Branch(then, other, self.line(node), cond))

    def _arm(self, node: Node | None) -> tuple:  # type: ignore[type-arg]
        if node is None:
            return ()
        return self.capture(lambda: self.stmt(node))

    def _alt_chain(self, alternatives: list[Node]) -> tuple:  # type: ignore[type-arg]
        head, rest = alternatives[0], alternatives[1:]
        if head.type == "else_clause":
            return self.block(head.child_by_field_name("body") or head)

        def run() -> None:
            cond = self.expr(head.child_by_field_name("condition"))
            then = self._arm(head.child_by_field_name("body"))
            self.emit(Branch(then, self._alt_chain(rest) if rest else (), self.line(head), cond))

        return self.capture(run)

    def s_foreach_statement(self, node: Node) -> None:
        kids = self.named(node)
        iterable = self.expr(kids[0]) if kids else Unknown("foreach")

        def run() -> None:
            for target in kids[1:-1]:
                inner = self.named(target) if target.type == "pair" else [target]
                for t in inner:
                    self._bind(t, Index(iterable, Unknown("iter")), node)
            body = node.child_by_field_name("body") or (kids[-1] if kids else None)
            if body is not None:
                self.stmt(body)

        self.emit(Loop(self.capture(run), self.line(node)))

    def s_for_statement(self, node: Node) -> None:
        def run() -> None:
            for child in self.named(node):
                self.stmt(child) if child.type.endswith("statement") else self.expr(child)

        self.emit(Loop(self.capture(run), self.line(node)))

    s_while_statement = s_for_statement
    s_do_statement = s_for_statement

    def s_try_statement(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        if body is not None:
            self.stmt(body)
        for child in node.children:
            if child.type == "catch_clause":
                self.emit(
                    Branch(self.block(child.child_by_field_name("body")), (), self.line(child))
                )
            elif child.type == "finally_clause":
                self.stmt(child.child_by_field_name("body") or child)

    def s_switch_statement(self, node: Node) -> None:
        self.expr(node.child_by_field_name("condition"))
        body = node.child_by_field_name("body")
        for case in self.named(body) if body is not None else []:
            self.emit(Branch(self.block(case), (), self.line(case)))

    def s_unset_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.expr(child)

    def s_global_declaration(self, node: Node) -> None:
        return None

    # --- expressions ----------------------------------------------------------------------

    def x_variable_name(self, node: Node) -> Operand:
        return Var(self._var_name(node))

    def x_name(self, node: Node) -> Operand:
        return Const(self.text(node))

    x_qualified_name = x_name

    def x_member_access_expression(self, node: Node) -> Operand:
        return Field(
            self.expr(node.child_by_field_name("object")),
            self._name(node.child_by_field_name("name")),
        )  # noqa: E501

    x_nullsafe_member_access_expression = x_member_access_expression

    def x_subscript_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        key = self.expr(kids[1]) if len(kids) > 1 else Unknown("append")
        return Index(self.expr(kids[0]), key)

    def _args(self, node: Node | None) -> tuple[list[Operand], list[tuple[str, Operand]]]:
        args: list[Operand] = []
        kwargs: list[tuple[str, Operand]] = []
        for arg in self.named(node) if node is not None else []:
            name = arg.child_by_field_name("name")
            inner = self.named(arg)
            value = inner[-1] if inner else arg
            if name is not None and value is not name:
                kwargs.append((self.text(name), self.expr(value)))
            elif value.type in ("anonymous_function", "arrow_function"):
                args.append(self._function(value))
            else:
                args.append(self.expr(value))
        return args, kwargs

    def x_function_call_expression(self, node: Node) -> Operand:
        fn = node.child_by_field_name("function")
        args, kwargs = self._args(node.child_by_field_name("arguments"))
        if fn is not None and fn.type in ("name", "qualified_name"):
            return self.call(node, self._name(fn), None, args, kwargs)
        recv = self.expr(fn) if fn is not None else None
        return self.call(node, "?", recv, args, kwargs)

    def x_member_call_expression(self, node: Node) -> Operand:
        obj = node.child_by_field_name("object")
        method = self._name(node.child_by_field_name("name"))
        args, kwargs = self._args(node.child_by_field_name("arguments"))
        recv = self.expr(obj)
        dotted = (
            self.text(obj).lstrip("$") if obj is not None and obj.type == "variable_name" else None
        )  # noqa: E501
        return self.call(
            node, f"{dotted}.{method}" if dotted else f"?.{method}", recv, args, kwargs
        )  # noqa: E501

    x_nullsafe_member_call_expression = x_member_call_expression

    def x_scoped_call_expression(self, node: Node) -> Operand:
        scope = self._name(node.child_by_field_name("scope"))
        method = self._name(node.child_by_field_name("name"))
        args, kwargs = self._args(node.child_by_field_name("arguments"))
        return self.call(node, f"{scope}::{method}", None, args, kwargs)

    def x_object_creation_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        cls = next((self._name(k) for k in kids if k.type in ("name", "qualified_name")), "?")
        arguments = next((k for k in kids if k.type == "arguments"), None)
        args, kwargs = self._args(arguments)
        return self.call(node, f"new {cls}", None, args, kwargs)

    def x_encapsed_string(self, node: Node) -> Operand:
        parts = [
            self.expr(c)
            for c in self.named(node)
            if c.type not in ("string_content", "escape_sequence", "string_value")
        ]
        return self._concat(parts, node) if parts else Const(self.text(node)[1:-1])

    x_heredoc = x_encapsed_string

    def x_string(self, node: Node) -> Operand:
        return Const(self.text(node)[1:-1])

    def x_string_content(self, node: Node) -> Operand:
        return Const(self.text(node))

    x_string_value = x_string_content

    def x_integer(self, node: Node) -> Operand:
        try:
            return Const(int(self.text(node).replace("_", ""), 0))
        except ValueError:
            return Const(self.text(node))

    def x_float(self, node: Node) -> Operand:
        try:
            return Const(float(self.text(node)))
        except ValueError:
            return Const(self.text(node))

    def x_boolean(self, node: Node) -> Operand:
        return Const(self.text(node).lower() == "true")

    def x_null(self, node: Node) -> Operand:
        return Const(None)

    def x_parenthesized_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("empty")

    def x_binary_expression(self, node: Node) -> Operand:
        return self._concat(
            [
                self.expr(node.child_by_field_name("left")),
                self.expr(node.child_by_field_name("right")),
            ],
            node,
        )

    def x_unary_op_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[-1]) if kids else Unknown("unary")

    x_cast_expression = x_unary_op_expression
    x_clone_expression = x_unary_op_expression
    x_error_suppression_expression = x_unary_op_expression
    x_print_intrinsic = x_unary_op_expression

    def x_conditional_expression(self, node: Node) -> Operand:
        return self._concat([self.expr(k) for k in self.named(node)], node)

    def x_assignment_expression(self, node: Node) -> Operand:
        value = self.expr(node.child_by_field_name("right"))
        self._bind(node.child_by_field_name("left"), value, node)
        return value

    def x_augmented_assignment_expression(self, node: Node) -> Operand:
        left = node.child_by_field_name("left")
        right = self.expr(node.child_by_field_name("right"))
        current = self.expr(left)
        dst = self.temp()
        self.emit(Concat(dst, (current, right), self.line(node)))
        self._bind(left, dst, node)
        return dst

    def x_array_creation_expression(self, node: Node) -> Operand:
        parts: list[Operand] = []
        for element in self.named(node):
            inner = self.named(element)
            parts.append(self.expr(inner[-1]) if inner else Unknown("element"))
        return self._concat(parts, node)

    def x_anonymous_function(self, node: Node) -> Operand:
        return self._function(node)

    x_arrow_function = x_anonymous_function

    def x_throw_expression(self, node: Node) -> Operand:
        for child in self.named(node):
            self.expr(child)
        self.emit(Return(None, self.line(node)))  # control does not continue
        return Unknown("throw")

    def x_include_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.call(node, "include", None, [self.expr(k) for k in kids], [])

    x_include_once_expression = x_include_expression
    x_require_expression = x_include_expression
    x_require_once_expression = x_include_expression

    def x_shell_command_expression(self, node: Node) -> Operand:
        parts = [self.expr(c) for c in self.named(node) if c.type != "string_content"]
        return self.call(node, "shell_exec", None, parts, [])

    def x_exit_statement(self, node: Node) -> Operand:
        return Unknown("exit")
