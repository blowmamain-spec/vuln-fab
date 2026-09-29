"""Laravel migrations -> final-state tables (``Schema::create`` / ``Schema::table`` in ``up()``)."""

from __future__ import annotations

import re

from tree_sitter import Node

from vulnfab.core.models import Column, SchemaModel, SourceFile, Table, Unresolved
from vulnfab.core.parsing import ParseFailure, parse_file
from vulnfab.core.sensitive import SENSITIVE_NAME
from vulnfab.plugins.laravel import phpast as ast

SCHEMA = "db"
TEXTUAL = ("string", "text", "longText", "mediumText", "binary", "char", "tinyText", "blob")
SIMPLE_TYPES = {
    "string", "text", "longText", "mediumText", "tinyText", "char", "integer", "bigInteger",
    "smallInteger", "mediumInteger", "tinyInteger", "unsignedInteger", "unsignedBigInteger",
    "unsignedSmallInteger", "unsignedTinyInteger", "float", "double", "decimal", "boolean",
    "date", "dateTime", "dateTimeTz", "timestamp", "timestampTz", "time", "timeTz", "year",
    "json", "jsonb", "uuid", "ulid", "binary", "enum", "set", "ipAddress", "macAddress",
    "geometry", "point", "increments", "bigIncrements", "smallIncrements", "mediumIncrements",
    "tinyIncrements", "foreignId", "foreignUuid", "foreignUlid", "id", "blob",
}  # fmt: skip


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name.rsplit("\\", 1)[-1]).lower()


def pluralize(word: str) -> str:
    if word.endswith("y") and not word.endswith(("ay", "ey", "oy", "uy")):
        return word[:-1] + "ies"
    if word.endswith(("s", "x", "z", "ch", "sh")):
        return word + "es"
    return word + "s"


def table_for_class(name: str) -> str:
    return pluralize(snake(name))


def _closure(call_args: list[Node]) -> Node | None:
    for a in call_args[1:]:
        if a.type in ("anonymous_function", "arrow_function"):
            return a
    return None


def _statements(closure: Node) -> list[Node]:
    body = closure.child_by_field_name("body")
    if body is None:
        return []
    if body.type == "compound_statement":
        out = []
        for stmt in body.children:
            if stmt.type == "expression_statement":
                named = [c for c in stmt.children if c.is_named]
                if named:
                    out.append(named[0])
        return out
    return [body]


def _param_name(closure: Node, source: bytes) -> str:
    params = closure.child_by_field_name("parameters")
    if params is not None:
        for p in params.children:
            var = next((c for c in p.children if c.type == "variable_name"), None)
            if var is not None:
                return ast.text(var, source).lstrip("$")
    return "table"


class MigrationBuilder:
    def __init__(self) -> None:
        self.model = SchemaModel()

    # --- entry --------------------------------------------------------------------------------

    def apply_file(self, path: str, text: str) -> None:
        try:
            pf = parse_file(SourceFile(path, "php", text, "0" * 64))
        except ParseFailure as exc:
            self.model.unresolved.append(Unresolved("parse_error", path, 1, str(exc)))
            return
        source = pf.source
        ups = [
            n
            for n in ast.walk(pf.tree.root_node)
            if n.type == "method_declaration"
            and ast.text(n.child_by_field_name("name"), source) == "up"
        ]
        for method in ups:
            for stmt in ast.walk(method):
                if stmt.type != "expression_statement":
                    continue
                named = [c for c in stmt.children if c.is_named]
                if not named:
                    continue
                chain = ast.chain_of(named[0], source)
                if chain is None or chain.root != "Schema" or not chain.links:
                    continue
                self._schema_call(path, source, chain)
        if not ups and "Schema::" in text:
            self.model.unresolved.append(
                Unresolved("migration_shape", path, 1, "no up() method found in this migration")
            )

    # --- Schema::xxx --------------------------------------------------------------------------

    def _schema_call(self, path: str, source: bytes, chain: ast.Chain) -> None:
        link = next(
            (
                item
                for item in chain.links
                if item.name in ("create", "table", "drop", "dropIfExists", "rename")
            ),
            None,
        )
        if link is None or not link.args:
            return
        name = ast.string_value(link.args[0], source)
        if name is None:
            self.model.unresolved.append(
                Unresolved(
                    "dynamic_table",
                    path,
                    ast.line(link.node, source),
                    "table name is not a literal",
                )
            )
            return
        key = f"{SCHEMA}.{name}"
        line = ast.line(link.node, source)
        if link.name in ("drop", "dropIfExists"):
            self.model.tables.pop(key, None)
            return
        if link.name == "rename":
            new = ast.string_value(link.args[1], source) if len(link.args) > 1 else None
            table = self.model.tables.pop(key, None)
            if table is not None and new:
                table.name = new
                self.model.tables[f"{SCHEMA}.{new}"] = table
            return
        if link.name == "create":
            table = Table(
                name=name,
                schema=SCHEMA,
                file=path,
                line=line,
                end_line=ast.end_line(link.node, source),
            )
            self.model.tables[key] = table
        else:
            table = self.model.tables.get(key)
            if table is None:
                table = Table(name=name, schema=SCHEMA, file=path, line=line, external=True)
                self.model.tables[key] = table
        closure = _closure(link.args)
        if closure is None:
            return
        var = _param_name(closure, source)
        for expr in _statements(closure):
            table_chain = ast.chain_of(expr, source)
            if (
                table_chain is None
                or table_chain.scoped
                or table_chain.root != var
                or not table_chain.links
            ):
                continue
            self._table_op(table, path, source, table_chain)

    # --- $table->xxx() ------------------------------------------------------------------------

    def _table_op(self, table: Table, path: str, source: bytes, chain: ast.Chain) -> None:
        first = chain.links[0]
        method = first.name
        arg0 = ast.string_value(first.args[0], source) if first.args else None
        rest = chain.links[1:]

        def add(name: str, kind: str, links: list[ast.Link]) -> Column:
            column = self._column(table, name, kind, links, source)
            return column

        if method == "timestamps" or method == "timestampsTz" or method == "nullableTimestamps":
            add("created_at", "timestamp", [])
            add("updated_at", "timestamp", [])
        elif method in ("softDeletes", "softDeletesTz"):
            add(arg0 or "deleted_at", "timestamp", rest)
        elif method == "rememberToken":
            add("remember_token", "string", rest)
        elif method == "morphs" or method == "nullableMorphs" or method == "uuidMorphs":
            if arg0:
                add(f"{arg0}_id", "unsignedBigInteger", rest)
                add(f"{arg0}_type", "string", rest)
        elif method == "foreignIdFor":
            ref = ast.class_ref(first.args[0], source) if first.args else None
            if ref:
                col = add(f"{snake(ref)}_id", "foreignId", rest)
                col.references = col.references or table_for_class(ref)
        elif method == "id":
            add(arg0 or "id", "id", rest)
        elif method in ("foreign",):
            self._foreign(table, arg0, rest, source)
        elif method in ("unique", "primary") and arg0:
            for col in table.columns:
                if col.name == arg0:
                    col.unique = True
        elif method == "dropColumn" or method == "dropColumns":
            names = ast.string_list(first.args[0], source) if first.args else None
            for n in names or [a for a in [ast.string_value(x, source) for x in first.args] if a]:
                table.columns = [c for c in table.columns if c.name != n]
        elif method == "renameColumn" and len(first.args) >= 2:
            old, new = (
                ast.string_value(first.args[0], source),
                ast.string_value(first.args[1], source),
            )
            for col in table.columns:
                if col.name == old and new:
                    col.name = new
        elif method in ("dropTimestamps", "dropSoftDeletes", "dropRememberToken"):
            drop = {
                "dropTimestamps": {"created_at", "updated_at"},
                "dropSoftDeletes": {"deleted_at"},
                "dropRememberToken": {"remember_token"},
            }[method]
            table.columns = [c for c in table.columns if c.name not in drop]
        elif method in SIMPLE_TYPES:
            add(arg0 or "id", method, rest)

    def _column(
        self, table: Table, name: str, kind: str, links: list[ast.Link], source: bytes
    ) -> Column:
        existing = next((c for c in table.columns if c.name == name), None)
        column = existing or Column(name, kind, nullable=False)
        if existing is None:
            table.columns.append(column)
        column.type = kind
        column.sensitive_hint = bool(SENSITIVE_NAME.search(name) and kind in TEXTUAL)
        for link in links:
            if link.name == "nullable":
                column.nullable = not (link.args and ast.text(link.args[0], source) == "false")
            elif link.name in ("unique", "primary"):
                column.unique = True
            elif link.name == "default" and link.args:
                column.default = ast.text(link.args[0], source)
            elif link.name == "constrained":
                target = ast.string_value(link.args[0], source) if link.args else None
                column.references = target or pluralize(re.sub(r"_id$", "", name))
            elif link.name == "on" and link.args:
                column.references = ast.string_value(link.args[0], source) or column.references
        return column

    def _foreign(
        self, table: Table, column_name: str | None, links: list[ast.Link], source: bytes
    ) -> None:
        if not column_name:
            return
        column = next((c for c in table.columns if c.name == column_name), None)
        if column is None:
            return
        for link in links:
            if link.name == "on" and link.args:
                column.references = ast.string_value(link.args[0], source) or column.references
