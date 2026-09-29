"""Small helpers over the tree-sitter PHP grammar (calls, chains, literals)."""

from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

CALL_TYPES = ("member_call_expression", "scoped_call_expression", "function_call_expression")


def text(node: Node | None, source: bytes) -> str:
    return (
        "" if node is None else source[node.start_byte : node.end_byte].decode("utf-8", "replace")
    )


def line(node: Node, source: bytes) -> int:
    return source.count(b"\n", 0, node.start_byte) + 1


def end_line(node: Node, source: bytes) -> int:
    return source.count(b"\n", 0, node.end_byte) + 1


def walk(node: Node):  # type: ignore[no-untyped-def]
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def arguments(call: Node) -> list[Node]:
    """Expression nodes of a call's argument list (named-argument labels are dropped)."""
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    out: list[Node] = []
    for arg in args.children:
        if arg.type != "argument":
            continue
        named = [c for c in arg.children if c.is_named]
        if named:
            out.append(named[-1])
    return out


@dataclass
class Link:
    name: str
    args: list[Node]
    node: Node


@dataclass
class Chain:
    root: str  # class name for Route::x(), variable name for $table->x(), else ""
    scoped: bool
    links: list[Link] = field(default_factory=list)  # in call order


def chain_of(node: Node, source: bytes) -> Chain | None:
    """Flatten ``Root::a(...)->b(...)->c(...)`` (or ``$var->a()->b()``) into ordered links."""
    links: list[Link] = []
    current: Node | None = node
    while current is not None:
        if current.type == "member_call_expression":
            name = text(current.child_by_field_name("name"), source)
            links.append(Link(name, arguments(current), current))
            current = current.child_by_field_name("object")
        elif current.type == "scoped_call_expression":
            name = text(current.child_by_field_name("name"), source)
            links.append(Link(name, arguments(current), current))
            scope = text(current.child_by_field_name("scope"), source)
            links.reverse()
            return Chain(scope.lstrip("\\"), True, links)
        elif current.type == "variable_name":
            links.reverse()
            return Chain(text(current, source).lstrip("$"), False, links)
        elif current.type == "function_call_expression":
            fn = text(current.child_by_field_name("function"), source)
            links.append(Link(fn, arguments(current), current))
            links.reverse()
            return Chain("", False, links)  # helper function chain: auth()->id(), request()->x
        else:
            return None
    return None


def string_value(node: Node | None, source: bytes) -> str | None:
    """Literal string content, or ``Foo::class`` as ``"Foo"`` with a ``::class`` marker removed."""
    if node is None:
        return None
    if node.type in ("string", "encapsed_string"):
        if any(c.type in ("variable_name", "member_access_expression") for c in walk(node)):
            return None
        return "".join(text(c, source) for c in node.children if c.type == "string_content")
    if node.type == "integer" or node.type == "float":
        return text(node, source)
    return None


def class_ref(node: Node | None, source: bytes) -> str | None:
    """``Foo::class`` / ``\\App\\Foo::class`` -> ``Foo`` / ``App\\Foo``."""
    if node is not None and node.type == "class_constant_access_expression":
        kids = [c for c in node.children if c.is_named]
        if len(kids) == 2 and text(kids[1], source) == "class":
            return text(kids[0], source).lstrip("\\")
    return None


def array_items(node: Node | None, source: bytes) -> list[tuple[str | None, Node]]:
    """(key, value) pairs of an array literal; key is None for list items."""
    if node is None or node.type != "array_creation_expression":
        return []
    out: list[tuple[str | None, Node]] = []
    for element in node.children:
        if element.type != "array_element_initializer":
            continue
        named = [c for c in element.children if c.is_named]
        if len(named) == 2:
            out.append((string_value(named[0], source), named[1]))
        elif named:
            out.append((None, named[0]))
    return out


def string_list(node: Node | None, source: bytes) -> list[str] | None:
    """A string or an array of strings -> list; anything else -> None."""
    if node is None:
        return None
    single = string_value(node, source)
    if single is not None:
        return [single]
    if node.type == "array_creation_expression":
        values = [string_value(v, source) for _, v in array_items(node, source)]
        return [v for v in values if v is not None] if all(v is not None for v in values) else None
    return None
