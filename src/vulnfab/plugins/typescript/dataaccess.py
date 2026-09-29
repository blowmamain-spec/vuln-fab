"""Extract supabase-js data access facts (`DataAccess`) from parsed TypeScript/JavaScript."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from tree_sitter import Node

from vulnfab.core.models import ClientKind, DataAccess, ParsedFile, Unresolved
from vulnfab.core.parsing import node_lines, node_text, walk
from vulnfab.plugins.typescript.resolve import resolve_module

CLIENT_FACTORIES = frozenset(
    {
        "createClient", "createBrowserClient", "createServerClient", "createRouteHandlerClient",
        "createServerComponentClient", "createClientComponentClient", "createPagesBrowserClient",
        "createPagesServerClient", "createMiddlewareClient", "createServerSupabaseClient",
    }
)  # fmt: skip
SESSION_FACTORIES = CLIENT_FACTORIES - {"createClient"}  # auth-helpers/ssr: anon key + user session
OPERATIONS = {"select": "select", "insert": "insert", "update": "update", "upsert": "upsert",
              "delete": "delete"}  # fmt: skip
FILTER_METHODS = frozenset(
    {"eq", "neq", "gt", "gte", "lt", "lte", "like", "ilike", "is", "in", "contains", "match",
     "filter", "not"}
)  # fmt: skip
NOT_CLIENTS = frozenset(
    {"Array", "Buffer", "Object", "Set", "Map", "Promise", "Observable", "Uint8Array", "rxjs"}
)
SERVICE_RE = re.compile(r"service[_-]?role|service[_-]?key|SERVICE_ROLE|serviceRole", re.I)
ANON_RE = re.compile(r"anon|publishable", re.I)


def classify_key(text: str) -> ClientKind:
    if SERVICE_RE.search(text):
        return "service_role"
    if ANON_RE.search(text):
        return "anon"
    return "unknown"


@dataclass
class FileFacts:
    path: str
    pf: ParsedFile
    clients: dict[str, ClientKind] = field(default_factory=dict)  # local var -> kind
    factories: dict[str, ClientKind] = field(default_factory=dict)  # local function -> kind
    exports: dict[str, tuple[str, str]] = field(
        default_factory=dict
    )  # exported -> ("client"|"factory", ...)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (module, name)
    constants: dict[str, str] = field(default_factory=dict)  # const NAME = "literal"
    factory_calls: dict[str, str] = field(
        default_factory=dict
    )  # `const db = getAdmin()`: db -> getAdmin


def _unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type in (
        "await_expression", "non_null_expression", "as_expression", "satisfies_expression",
        "parenthesized_expression", "type_assertion",
    ):  # fmt: skip
        named = [c for c in node.children if c.is_named]
        if not named:
            return None
        node = named[-1] if node.type == "type_assertion" else named[0]
    return node


def _string_value(node: Node | None, source: bytes) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return node_text(node, source)[1:-1]
    if node.type == "template_string" and not any(
        c.type == "template_substitution" for c in node.children
    ):
        return node_text(node, source)[1:-1]
    return None


def _call_name(call: Node, source: bytes) -> str | None:
    fn = _unwrap(call.child_by_field_name("function"))
    if fn is None:
        return None
    if fn.type == "identifier":
        return node_text(fn, source)
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        return node_text(prop, source) if prop is not None else None
    return None


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [c for c in args.children if c.is_named and c.type != "comment"] if args else []


def client_kind_of_call(call: Node, source: bytes) -> ClientKind | None:
    """Kind of client created by ``createClient(...)``-like call, else ``None``."""
    name = _call_name(call, source)
    if name not in CLIENT_FACTORIES:
        return None
    args = _arguments(call)
    if name in SESSION_FACTORIES and (len(args) < 2 or args[0].type == "object"):
        return "user"  # auth-helpers style: anon key + cookie session
    key_text = node_text(args[1], source) if len(args) >= 2 else ""
    kind = classify_key(key_text)
    if name in SESSION_FACTORIES and kind in ("anon", "unknown"):
        return "user"
    return kind


def collect_facts(pf: ParsedFile) -> FileFacts:
    facts = FileFacts(pf.path, pf)
    src = pf.source
    root = pf.tree.root_node
    for node in walk(root):
        t = node.type
        if t == "import_statement":
            _collect_import(facts, node, src)
        elif t == "variable_declarator":
            _collect_declarator(facts, node, src)
        elif t in ("function_declaration", "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                kind = _returned_client_kind(node, src)
                if kind:
                    facts.factories[node_text(name_node, src)] = kind
        elif t == "export_statement":
            _collect_export(facts, node, src)
    # exports declared as `export const x = ...` / `export function f`
    for node in root.children:
        if node.type == "export_statement":
            decl = node.child_by_field_name("declaration")
            if decl is None:
                continue
            for d in walk(decl):
                if d.type == "variable_declarator":
                    name = d.child_by_field_name("name")
                    if name is not None and name.type == "identifier":
                        n = node_text(name, src)
                        if n in facts.clients:
                            facts.exports[n] = ("client", n)
                        elif n in facts.factories:
                            facts.exports[n] = ("factory", n)
                elif d.type == "function_declaration":
                    name = d.child_by_field_name("name")
                    if name is not None and node_text(name, src) in facts.factories:
                        facts.exports[node_text(name, src)] = ("factory", node_text(name, src))
    return facts


def _returned_client_kind(fn: Node, src: bytes) -> ClientKind | None:
    for n in walk(fn):
        if n.type == "return_statement":
            named = [c for c in n.children if c.is_named]
            call = _unwrap(named[0]) if named else None
            if call is not None and call.type == "call_expression":
                kind = client_kind_of_call(call, src)
                if kind:
                    return kind
    return None


def _collect_declarator(facts: FileFacts, node: Node, src: bytes) -> None:
    name = node.child_by_field_name("name")
    value = _unwrap(node.child_by_field_name("value"))
    if name is None or name.type != "identifier" or value is None:
        return
    local = node_text(name, src)
    literal = _string_value(value, src)
    if literal is not None:
        facts.constants[local] = literal
        return
    if value.type == "call_expression":
        kind = client_kind_of_call(value, src)
        if kind:
            facts.clients[local] = kind
            return
        called = _call_name(value, src)
        if called and called in facts.factories:
            facts.clients[local] = facts.factories[called]
        elif called:
            facts.factory_calls[local] = called
    elif value.type in ("arrow_function", "function_expression", "function"):
        kind = None
        body = value.child_by_field_name("body")
        if body is not None:
            inner = _unwrap(body)
            if inner is not None and inner.type == "call_expression":
                kind = client_kind_of_call(inner, src)
            if kind is None:
                kind = _returned_client_kind(value, src)
        if kind:
            facts.factories[local] = kind


def _collect_import(facts: FileFacts, node: Node, src: bytes) -> None:
    source = node.child_by_field_name("source")
    module = _string_value(source, src)
    if module is None:
        return
    for child in node.children:
        if child.type != "import_clause":
            continue
        for part in child.children:
            if part.type == "identifier":
                facts.imports[node_text(part, src)] = (module, "default")
            elif part.type == "named_imports":
                for spec in part.children:
                    if spec.type != "import_specifier":
                        continue
                    name = spec.child_by_field_name("name")
                    alias = spec.child_by_field_name("alias")
                    if name is not None:
                        original = node_text(name, src)
                        local = node_text(alias, src) if alias is not None else original
                        facts.imports[local] = (module, original)


def _collect_export(facts: FileFacts, node: Node, src: bytes) -> None:
    value = node.child_by_field_name("value")  # export default <expr>
    if value is not None:
        inner = _unwrap(value)
        if inner is not None and inner.type == "call_expression":
            kind = client_kind_of_call(inner, src)
            if kind:
                facts.clients["default"] = kind
                facts.exports["default"] = ("client", "default")
        elif inner is not None and inner.type == "identifier":
            ident = node_text(inner, src)
            if ident in facts.clients:
                facts.exports["default"] = ("client", ident)
    for child in node.children:
        if child.type == "export_clause":
            for spec in child.children:
                if spec.type == "export_specifier":
                    name_node = spec.child_by_field_name("name")
                    alias = spec.child_by_field_name("alias")
                    if name_node is not None:
                        original = node_text(name_node, src)
                        exported = node_text(alias, src) if alias is not None else original
                        facts.exports[exported] = ("ref", original)


class Project:
    """All files of a TS/JS project, able to resolve a client identifier across imports."""

    def __init__(self, files: dict[str, ParsedFile]) -> None:
        self.facts = {path: collect_facts(pf) for path, pf in files.items()}
        self.known = set(files)

    def _export_kind(self, path: str, name: str, seen: set[tuple[str, str]]) -> ClientKind | None:
        if (path, name) in seen or path not in self.facts:
            return None
        seen.add((path, name))
        facts = self.facts[path]
        target = facts.exports.get(name)
        if target is None:
            return None
        what, ref = target
        if what == "client":
            return facts.clients.get(ref)
        if what == "ref":
            return facts.clients.get(ref) or self._export_kind(path, ref, seen)
        return None

    def client_kind(self, path: str, identifier: str) -> ClientKind | None:
        facts = self.facts[path]
        if identifier in facts.clients:
            return facts.clients[identifier]
        if identifier in facts.factory_calls:
            return self.factory_kind(path, facts.factory_calls[identifier])
        imported = facts.imports.get(identifier)
        if imported is None:
            return None
        module, name = imported
        target = resolve_module(path, module, self.known)
        if target is None:
            return None
        # factories: `const c = getClient()` handled at declaration time; direct client export here
        return self._export_kind(target, name, set())

    def factory_kind(self, path: str, name: str) -> ClientKind | None:
        facts = self.facts[path]
        if name in facts.factories:
            return facts.factories[name]
        imported = facts.imports.get(name)
        if imported is None:
            return None
        module, original = imported
        target = resolve_module(path, module, self.known)
        if target is None or target not in self.facts:
            return None
        tf = self.facts[target]
        ref = tf.exports.get(original)
        if ref and ref[0] == "factory":
            return tf.factories.get(ref[1])
        return None


def _chain_from(call: Node) -> list[Node]:
    """The `.from(...)` call followed by every chained call (`.select().eq()...`)."""
    chain = [call]
    current = call
    while True:
        parent = current.parent
        while parent is not None and parent.type in (
            "await_expression",
            "parenthesized_expression",
            "non_null_expression",
        ):  # noqa: E501
            parent = parent.parent
        if parent is None or parent.type != "member_expression":
            break
        grand = parent.parent
        if (
            grand is None
            or grand.type != "call_expression"
            or grand.child_by_field_name("function") != parent
        ):  # noqa: E501
            break
        chain.append(grand)
        current = grand
    return chain


def _resolve_object(project: Project, facts: FileFacts, obj: Node | None) -> ClientKind | None:
    obj = _unwrap(obj)
    if obj is None:
        return None
    src = facts.pf.source
    if obj.type == "identifier":
        name = node_text(obj, src)
        if name in NOT_CLIENTS:
            return None
        return project.client_kind(facts.path, name) or "unknown"
    if obj.type == "call_expression":
        direct = client_kind_of_call(obj, src)
        if direct:
            return direct
        called = _call_name(obj, src)
        if called:
            fkind = project.factory_kind(facts.path, called)
            if fkind:
                return fkind
    return "unknown"


def _table_name(facts: FileFacts, arg: Node | None) -> str | None:
    literal = _string_value(arg, facts.pf.source)
    if literal is not None:
        return literal
    arg = _unwrap(arg)
    if arg is not None and arg.type == "identifier":
        return facts.constants.get(node_text(arg, facts.pf.source))
    return None


def extract(files: dict[str, ParsedFile]) -> tuple[list[DataAccess], list[Unresolved]]:
    project = Project(files)
    accesses: list[DataAccess] = []
    unresolved: list[Unresolved] = []
    for path in sorted(files):
        facts = project.facts[path]
        src = facts.pf.source
        for node in walk(facts.pf.tree.root_node):
            if node.type != "call_expression":
                continue
            fn = _unwrap(node.child_by_field_name("function"))
            if fn is None or fn.type != "member_expression":
                continue
            prop = fn.child_by_field_name("property")
            if prop is None:
                continue
            method = node_text(prop, src)
            if method not in ("from", "rpc"):
                continue
            obj = _unwrap(fn.child_by_field_name("object"))
            schema: str | None = None
            if (
                obj is not None
                and obj.type == "call_expression"
                and _call_name(obj, src) == "schema"
            ):
                schema_args = _arguments(obj)
                schema = _string_value(schema_args[0], src) if schema_args else None
                inner_fn = _unwrap(obj.child_by_field_name("function"))
                obj = _unwrap(inner_fn.child_by_field_name("object")) if inner_fn else None
            if obj is not None and obj.type == "member_expression":
                inner_prop = obj.child_by_field_name("property")
                if inner_prop is not None and node_text(inner_prop, src) == "storage":
                    continue  # supabase.storage.from(bucket): not a table
            chain = _chain_from(node)
            calls = [(_call_name(c, src) or "", c) for c in chain[1:]]
            ops = [OPERATIONS[name] for name, _ in calls if name in OPERATIONS]
            if method == "from" and not ops:
                continue  # `Array.from(x)`, `Buffer.from(y)`, `rx.from(...)`: not a table query
            kind = _resolve_object(project, facts, obj)
            if kind is None:
                continue
            args = _arguments(node)
            table = _table_name(facts, args[0] if args else None)
            first, last = node_lines(chain[-1], src)
            start, _ = node_lines(node, src)
            first = min(first, start)
            if table is None:
                unresolved.append(
                    Unresolved("dynamic_table", path, start, "table name is not a constant")
                )
                continue
            filters: list[tuple[str, str]] = []
            for name, call in calls:
                if name not in FILTER_METHODS:
                    continue
                cargs = _arguments(call)
                if name == "match" and cargs and cargs[0].type == "object":
                    for pair in cargs[0].children:
                        if pair.type == "pair":
                            k = pair.child_by_field_name("key")
                            v = pair.child_by_field_name("value")
                            if k is not None and v is not None:
                                filters.append((node_text(k, src).strip("\"'"), node_text(v, src)))
                elif cargs:
                    column = _string_value(cargs[0], src)
                    value_index = 2 if name == "filter" else 1
                    value = node_text(cargs[value_index], src) if len(cargs) > value_index else ""
                    if column is not None:
                        filters.append((column, value))
            accesses.append(
                DataAccess(
                    table=table,
                    schema=schema,
                    op="rpc" if method == "rpc" else ops[0],  # type: ignore[arg-type]
                    file=path,
                    line=start,
                    filter_columns=tuple(c for c, _ in filters),
                    client_kind=kind,
                    end_line=last,
                    filters=tuple(filters),
                    snippet=node_text(chain[-1], src)[:300],
                )
            )
    return accesses, unresolved


def iter_calls(root: Node) -> Iterator[Node]:
    for n in walk(root):
        if n.type == "call_expression":
            yield n
