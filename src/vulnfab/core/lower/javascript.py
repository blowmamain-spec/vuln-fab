"""JavaScript / TypeScript / TSX -> TIR."""

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

_TRANSPARENT = frozenset(
    {"await_expression", "non_null_expression", "as_expression", "satisfies_expression",
     "parenthesized_expression", "type_assertion"}
)  # fmt: skip
_FUNCTIONS = frozenset({"arrow_function", "function_expression", "function", "generator_function"})


class JavaScriptLowerer(Lowerer):
    language = "javascript"

    def lower(self) -> ModuleIR:
        body = self.block(self.root)
        self.add_function("<module>", (), body, self.root)
        self.module.functions.insert(0, self.module.functions.pop())
        return self.module

    # --- helpers --------------------------------------------------------------------------

    def _inner(self, node: Node | None) -> Node | None:
        while node is not None and node.type in _TRANSPARENT:
            named = self.named(node)
            if not named:
                return None
            node = named[-1] if node.type == "type_assertion" else named[0]
        return node

    def _dotted(self, node: Node | None) -> str | None:
        node = self._inner(node)
        if node is None:
            return None
        if node.type in ("identifier", "this", "super"):
            return self.text(node)
        if node.type == "member_expression":
            base = self._dotted(node.child_by_field_name("object"))
            prop = self.text(node.child_by_field_name("property"))
            return f"{base}.{prop}" if base else None
        return None

    def _concat(self, parts: list[Operand], at: Node) -> Operand:
        if not parts:
            return Const("")
        dst = self.temp()
        self.emit(Concat(dst, tuple(parts), self.line(at)))
        return dst

    def _function(self, node: Node, name: str | None = None) -> Operand:
        """Lower a function-like node into its own FunctionIR; the value is a reference."""
        label = name or f"<anon@{self.line(node)}>"
        params, prologue = self._params(node)
        body_node = node.child_by_field_name("body")
        saved_class = self._class

        def run() -> None:
            for instr in prologue:
                self.emit(instr)
            if body_node is None:
                return
            if body_node.type == "statement_block":
                for child in self.named(body_node):
                    self.stmt(child)
            else:  # arrow function with an expression body
                self.emit(Return(self.expr(body_node), self.line(body_node)))

        body = self.capture(run)
        self._class = saved_class
        self.add_function(label, params, body, node)
        return Var(label)

    def _params(self, node: Node) -> tuple[tuple[str, ...], list]:  # type: ignore[type-arg]
        names: list[str] = []
        prologue: list = []  # type: ignore[type-arg]
        holder = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        if holder is None:
            return (), prologue
        items = [holder] if holder.type == "identifier" else self.named(holder)
        for i, item in enumerate(items):
            pattern = item
            if item.type in ("required_parameter", "optional_parameter"):
                pattern = item.child_by_field_name("pattern") or item
            if pattern.type == "assignment_pattern":
                pattern = pattern.child_by_field_name("left") or pattern
            if pattern.type == "rest_pattern":
                inner = self.named(pattern)
                pattern = inner[0] if inner else pattern
            if pattern.type == "identifier":
                names.append(self.text(pattern))
            elif pattern.type in ("object_pattern", "array_pattern"):
                holder_name = f"%arg{i}"
                names.append(holder_name)
                saved, self._code = self._code, []
                self._bind(pattern, Var(holder_name), pattern)
                prologue.extend(self._code)
                self._code = saved
        return tuple(names), prologue

    def _bind(self, target: Node | None, value: Operand, at: Node) -> None:
        if target is None:
            return
        t = target.type
        if t == "identifier":
            self.assign_to(Var(self.text(target)), value, at)
        elif t == "object_pattern":
            for child in self.named(target):
                if child.type == "shorthand_property_identifier_pattern":
                    name = self.text(child)
                    self.assign_to(Var(name), Field(value, name), at)
                elif child.type == "pair_pattern":
                    key = self.text(child.child_by_field_name("key"))
                    self._bind(child.child_by_field_name("value"), Field(value, key), at)
                elif child.type == "object_assignment_pattern":
                    left = child.child_by_field_name("left")
                    name = self.text(left)
                    self.assign_to(Var(name), Field(value, name), at)
                elif child.type == "rest_pattern":
                    for inner in self.named(child):
                        self._bind(inner, value, at)
        elif t == "array_pattern":
            for i, child in enumerate(self.named(target)):
                self._bind(child, Index(value, Const(i)), at)
        elif t == "assignment_pattern":
            self._bind(target.child_by_field_name("left"), value, at)
        elif t == "member_expression":
            self.assign_to(
                Field(
                    self.expr(target.child_by_field_name("object")),
                    self.text(target.child_by_field_name("property")),
                ),  # noqa: E501
                value,
                at,
            )
        elif t == "subscript_expression":
            self.assign_to(
                Index(
                    self.expr(target.child_by_field_name("object")),
                    self.expr(target.child_by_field_name("index")),
                ),  # noqa: E501
                value,
                at,
            )
        else:
            self.unhandled(target)

    # --- statements -----------------------------------------------------------------------

    def s_expression_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.expr(child)

    def s_statement_block(self, node: Node) -> None:
        for child in self.named(node):
            self.stmt(child)

    def s_lexical_declaration(self, node: Node) -> None:
        for decl in self.named(node):
            if decl.type != "variable_declarator":
                continue
            target = decl.child_by_field_name("name")
            value = self._inner(decl.child_by_field_name("value"))
            if value is None:
                continue
            if value.type in _FUNCTIONS and target is not None and target.type == "identifier":
                self._function(value, self.text(target))
                continue
            self._bind(target, self.expr(value), decl)

    s_variable_declaration = s_lexical_declaration

    def s_function_declaration(self, node: Node) -> None:
        self._function(node, self.text(node.child_by_field_name("name")))

    s_generator_function_declaration = s_function_declaration

    def s_class_declaration(self, node: Node) -> None:
        saved = self._class
        self._class = self.text(node.child_by_field_name("name"))
        try:
            body = node.child_by_field_name("body")
            for member in self.named(body) if body is not None else []:
                if member.type == "method_definition":
                    self._function(member, self.text(member.child_by_field_name("name")))
                elif member.type in ("public_field_definition", "field_definition"):
                    value = member.child_by_field_name("value")
                    if value is not None:
                        self.expr(value)
        finally:
            self._class = saved

    def s_return_statement(self, node: Node) -> None:
        kids = self.named(node)
        self.emit(Return(self.expr(kids[0]) if kids else None, self.line(node)))

    def s_throw_statement(self, node: Node) -> None:
        for child in self.named(node):
            self.expr(child)

    def s_if_statement(self, node: Node) -> None:
        self.expr(node.child_by_field_name("condition"))
        then = self._arm(node.child_by_field_name("consequence"))
        alt = node.child_by_field_name("alternative")
        other = ()
        if alt is not None:
            inner = self.named(alt)
            other = self._arm(inner[0]) if alt.type == "else_clause" and inner else self._arm(alt)
        self.emit(Branch(then, other, self.line(node)))

    def _arm(self, node: Node | None) -> tuple:  # type: ignore[type-arg]
        if node is None:
            return ()
        return self.capture(lambda: self.stmt(node))

    def s_for_statement(self, node: Node) -> None:
        def run() -> None:
            for field in ("initializer", "condition", "increment"):
                child = node.child_by_field_name(field)
                if child is not None:
                    self.stmt(child) if child.type.endswith(
                        ("declaration", "statement")
                    ) else self.expr(child)  # noqa: E501
            body = node.child_by_field_name("body")
            if body is not None:
                self.stmt(body)

        self.emit(Loop(self.capture(run), self.line(node)))

    def s_for_in_statement(self, node: Node) -> None:
        iterable = self.expr(node.child_by_field_name("right"))

        def run() -> None:
            left = node.child_by_field_name("left")
            if left is not None:
                self._bind(
                    left
                    if left.type != "variable_declarator"
                    else left.child_by_field_name("name"),
                    Index(iterable, Unknown("iter")),
                    node,
                )  # noqa: E501
            body = node.child_by_field_name("body")
            if body is not None:
                self.stmt(body)

        self.emit(Loop(self.capture(run), self.line(node)))

    def s_while_statement(self, node: Node) -> None:
        def run() -> None:
            self.expr(node.child_by_field_name("condition"))
            body = node.child_by_field_name("body")
            if body is not None:
                self.stmt(body)

        self.emit(Loop(self.capture(run), self.line(node)))

    s_do_statement = s_while_statement

    def s_try_statement(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        if body is not None:
            self.stmt(body)
        handler = node.child_by_field_name("handler")
        if handler is not None:
            self.emit(
                Branch(self.block(handler.child_by_field_name("body")), (), self.line(handler))
            )
        final = node.child_by_field_name("finalizer")
        if final is not None:
            self.stmt(final.child_by_field_name("body") or final)

    def s_switch_statement(self, node: Node) -> None:
        self.expr(node.child_by_field_name("value"))
        body = node.child_by_field_name("body")
        for case in self.named(body) if body is not None else []:
            self.emit(Branch(self.block(case), (), self.line(case)))

    def s_labeled_statement(self, node: Node) -> None:
        for child in self.named(node)[1:]:
            self.stmt(child)

    def s_export_statement(self, node: Node) -> None:
        decl = node.child_by_field_name("declaration")
        value = node.child_by_field_name("value")
        if decl is not None:
            self.stmt(decl)
        elif value is not None:
            self.expr(value)

    def s_import_statement(self, node: Node) -> None:
        source = node.child_by_field_name("source")
        module = self.text(source).strip("'\"`")
        for clause in node.children:
            if clause.type != "import_clause":
                continue
            for part in clause.children:
                if part.type == "identifier":
                    self.module.imports[self.text(part)] = (module, "default")
                elif part.type == "named_imports":
                    for spec in part.children:
                        if spec.type == "import_specifier":
                            name = self.text(spec.child_by_field_name("name"))
                            alias = spec.child_by_field_name("alias")
                            self.module.imports[self.text(alias) if alias else name] = (
                                module,
                                name,
                            )  # noqa: E501
                elif part.type == "namespace_import":
                    kids = self.named(part)
                    if kids:
                        self.module.imports[self.text(kids[0])] = (module, "*")

    IGNORED = Lowerer.IGNORED | frozenset(
        {"empty_statement", "type_alias_declaration", "interface_declaration", "enum_declaration",
         "debugger_statement", "ambient_declaration", "comment"}
    )  # fmt: skip

    # --- expressions ----------------------------------------------------------------------

    def x_identifier(self, node: Node) -> Operand:
        return Var(self.text(node))

    x_this = x_identifier
    x_super = x_identifier
    x_shorthand_property_identifier = x_identifier

    def x_undefined(self, node: Node) -> Operand:
        return Const(None)

    def x_member_expression(self, node: Node) -> Operand:
        return Field(
            self.expr(node.child_by_field_name("object")),
            self.text(node.child_by_field_name("property")),
        )  # noqa: E501

    def x_subscript_expression(self, node: Node) -> Operand:
        return Index(
            self.expr(node.child_by_field_name("object")),
            self.expr(node.child_by_field_name("index")),
        )  # noqa: E501

    def _call_args(self, arguments: Node | None) -> list[Operand]:
        out: list[Operand] = []
        for child in self.named(arguments) if arguments is not None else []:
            if child.type in _FUNCTIONS:
                out.append(self._function(child))
            else:
                out.append(self.expr(child))
        return out

    def x_call_expression(self, node: Node) -> Operand:
        fn = self._inner(node.child_by_field_name("function"))
        args = self._call_args(node.child_by_field_name("arguments"))
        recv: Operand | None = None
        callee = "?"
        if fn is not None and fn.type in ("identifier", "super", "import"):
            callee = self.text(fn)
        elif fn is not None and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            method = self.text(fn.child_by_field_name("property"))
            dotted = self._dotted(obj)
            recv = self.expr(obj)
            callee = f"{dotted}.{method}" if dotted else f"?.{method}"
        elif fn is not None:
            recv = self.expr(fn)
        return self.call(node, callee, recv, args, [])

    def x_new_expression(self, node: Node) -> Operand:
        ctor = self._dotted(node.child_by_field_name("constructor")) or "?"
        args = self._call_args(node.child_by_field_name("arguments"))
        return self.call(node, f"new {ctor}", None, args, [])

    def x_string(self, node: Node) -> Operand:
        return Const(self.text(node)[1:-1])

    def x_template_string(self, node: Node) -> Operand:
        parts = [
            self.expr(self.named(sub)[0])
            for sub in node.children
            if sub.type == "template_substitution" and self.named(sub)
        ]
        return self._concat(parts, node) if parts else Const(self.text(node)[1:-1])

    def x_number(self, node: Node) -> Operand:
        text = self.text(node).replace("_", "")
        try:
            return Const(int(text, 0))
        except ValueError:
            try:
                return Const(float(text))
            except ValueError:
                return Const(text)

    def x_true(self, node: Node) -> Operand:
        return Const(True)

    def x_false(self, node: Node) -> Operand:
        return Const(False)

    def x_null(self, node: Node) -> Operand:
        return Const(None)

    def x_regex(self, node: Node) -> Operand:
        return Const(self.text(node))

    def _wrapped(self, node: Node) -> Operand:
        inner = self._inner(node)
        return self.expr(inner) if inner is not None and inner is not node else Unknown(node.type)

    x_await_expression = _wrapped
    x_non_null_expression = _wrapped
    x_as_expression = _wrapped
    x_satisfies_expression = _wrapped
    x_parenthesized_expression = _wrapped
    x_type_assertion = _wrapped

    def x_binary_expression(self, node: Node) -> Operand:
        return self._concat(
            [
                self.expr(node.child_by_field_name("left")),
                self.expr(node.child_by_field_name("right")),
            ],
            node,
        )  # noqa: E501

    def x_unary_expression(self, node: Node) -> Operand:
        return self.expr(node.child_by_field_name("argument"))

    x_update_expression = x_unary_expression

    def x_ternary_expression(self, node: Node) -> Operand:
        return self._concat(
            [
                self.expr(node.child_by_field_name("consequence")),
                self.expr(node.child_by_field_name("alternative")),
            ],  # noqa: E501
            node,
        )

    def x_sequence_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        values = [self.expr(k) for k in kids]
        return values[-1] if values else Unknown("sequence")

    def x_assignment_expression(self, node: Node) -> Operand:
        value = self.expr(node.child_by_field_name("right"))
        left = node.child_by_field_name("left")
        if left is not None and left.type in ("object_pattern", "array_pattern"):
            self._bind(left, value, node)
        else:
            self._bind(left, value, node)
        return value

    def x_augmented_assignment_expression(self, node: Node) -> Operand:
        left = node.child_by_field_name("left")
        right = self.expr(node.child_by_field_name("right"))
        current = self.expr(left)
        dst = self.temp()
        self.emit(Concat(dst, (current, right), self.line(node)))
        self._bind(left, dst, node)
        return dst

    def x_object(self, node: Node) -> Operand:
        parts: list[Operand] = []
        for member in self.named(node):
            if member.type == "pair":
                parts.append(self.expr(member.child_by_field_name("value")))
            elif member.type == "shorthand_property_identifier":
                parts.append(Var(self.text(member)))
            elif member.type == "method_definition":
                parts.append(self._function(member, None))
            else:
                parts.append(self.expr(member))
        return self._concat(parts, node)

    def x_array(self, node: Node) -> Operand:
        return self._concat([self.expr(c) for c in self.named(node)], node)

    def x_spread_element(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("spread")

    def _fn_expr(self, node: Node) -> Operand:
        return self._function(node)

    x_arrow_function = _fn_expr
    x_function_expression = _fn_expr
    x_function = _fn_expr
    x_generator_function = _fn_expr

    def x_yield_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("yield")

    def x_class(self, node: Node) -> Operand:
        self.unhandled(node)
        return Unknown("class expression")

    def x_jsx_expression(self, node: Node) -> Operand:
        kids = self.named(node)
        return self.expr(kids[0]) if kids else Unknown("jsx")
