"""Eloquent model classes: ``$table``, ``$fillable``, ``$guarded``, ``$hidden``, relations."""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import ParseFailure, parse_file
from vulnfab.plugins.laravel import phpast as ast
from vulnfab.plugins.laravel.migrations import table_for_class

MODEL_BASES = {"Model", "Authenticatable", "Pivot", "MorphPivot", "User"}
RELATIONS = {
    "belongsTo", "hasOne", "hasMany", "belongsToMany", "morphTo", "morphMany", "morphOne",
    "hasOneThrough", "hasManyThrough", "morphToMany",
}  # fmt: skip


@dataclass
class EloquentModel:
    name: str
    file: str
    line: int
    table: str
    fillable: list[str] | None = None
    guarded: list[str] | None = None
    hidden: list[str] | None = None
    guarded_line: int = 0
    relations: list[tuple[str, str, str]] = field(default_factory=list)  # (kind, method, target)


def read_models(path: str, text: str) -> list[EloquentModel]:
    try:
        pf = parse_file(SourceFile(path, "php", text, "0" * 64))
    except ParseFailure:
        return []
    source = pf.source
    out: list[EloquentModel] = []
    for cls in ast.walk(pf.tree.root_node):
        if cls.type != "class_declaration":
            continue
        base = next((c for c in cls.children if c.type == "base_clause"), None)
        base_name = (
            ast.text(base, source).replace("extends", "").strip().rsplit("\\", 1)[-1]
            if base
            else ""
        )
        in_models_dir = "/Models/" in f"/{path}"
        if base_name not in MODEL_BASES and not (in_models_dir and base_name):
            continue
        name = ast.text(cls.child_by_field_name("name"), source)
        model = EloquentModel(name, path, ast.line(cls, source), table_for_class(name))
        body = cls.child_by_field_name("body")
        for member in body.children if body is not None else []:
            if member.type == "property_declaration":
                _property(model, member, source)
            elif member.type == "method_declaration":
                _relation(model, member, source)
        out.append(model)
    return out


def _property(model: EloquentModel, node: Node, source: bytes) -> None:
    for element in node.children:
        if element.type != "property_element":
            continue
        var = next((c for c in element.children if c.type == "variable_name"), None)
        value = next(
            (c for c in element.children if c.is_named and c.type != "variable_name"), None
        )
        if var is None:
            continue
        pname = ast.text(var, source).lstrip("$")
        if pname == "table":
            table = ast.string_value(value, source)
            if table:
                model.table = table
        elif pname in ("fillable", "guarded", "hidden"):
            items = ast.string_list(value, source)
            if items is None and value is not None and value.type == "array_creation_expression":
                items = []
            if pname == "guarded":
                model.guarded_line = ast.line(node, source)
            setattr(model, pname, items)


def _relation(model: EloquentModel, node: Node, source: bytes) -> None:
    method = ast.text(node.child_by_field_name("name"), source)
    for call in ast.walk(node):
        if call.type != "member_call_expression":
            continue
        chain = ast.chain_of(call, source)
        if chain is None or chain.root != "this" or not chain.links:
            continue
        link = chain.links[0]
        if link.name in RELATIONS and link.args:
            target = ast.class_ref(link.args[0], source) or ast.string_value(link.args[0], source)
            if target:
                model.relations.append((link.name, method, target.rsplit("\\", 1)[-1]))
            break
