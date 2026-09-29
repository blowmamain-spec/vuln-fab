"""tree-sitter parsing helpers shared by all plugins.

tree-sitter parsing itself is not interruptible from Python, so it is bounded by the file size
limit (see loader) and by :data:`MAX_AST_DEPTH`. Our own traversals take a :class:`Deadline`.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from functools import cache

import tree_sitter_javascript as tsjs
import tree_sitter_php as tsphp
import tree_sitter_python as tspy
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser, Tree

from vulnfab.core.models import ParsedFile, SourceFile

MAX_AST_DEPTH = 512

_LANGUAGE_FACTORIES = {
    "python": tspy.language,
    "javascript": tsjs.language,
    "typescript": tsts.language_typescript,
    "tsx": tsts.language_tsx,
    "php": tsphp.language_php,
}

PARSEABLE_LANGUAGES = frozenset(_LANGUAGE_FACTORIES)

_SYMBOL_NODE_TYPES = frozenset(
    {
        "function_definition", "class_definition",  # python, php
        "function_declaration", "class_declaration", "method_definition",  # js/ts
        "method_declaration", "interface_declaration",  # php/ts
    }
)  # fmt: skip


class ParseFailure(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class TimeoutExceeded(Exception):
    pass


class Deadline:
    """Cooperative time budget checked by our own traversals."""

    def __init__(self, seconds: float | None) -> None:
        self._end = None if seconds is None else time.monotonic() + seconds

    def check(self) -> None:
        if self._end is not None and time.monotonic() > self._end:
            raise TimeoutExceeded


@cache
def _language(name: str) -> Language:
    return Language(_LANGUAGE_FACTORIES[name]())


def parser_for(language: str) -> Parser | None:
    if language not in _LANGUAGE_FACTORIES:
        return None
    return Parser(_language(language))


def tree_depth(tree: Tree) -> int:
    """Maximum nesting depth, computed iteratively (safe on pathological input)."""
    cursor = tree.walk()
    depth = 0
    deepest = 0
    while True:
        deepest = max(deepest, depth)
        if cursor.goto_first_child():
            depth += 1
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return deepest
            depth -= 1


def parse_file(sf: SourceFile, *, max_depth: int = MAX_AST_DEPTH) -> ParsedFile:
    parser = parser_for(sf.language)
    if parser is None:
        raise ParseFailure("unsupported_language", sf.language)
    source = sf.text.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(source)
    except Exception as exc:  # tree-sitter raises generic errors on malformed state
        raise ParseFailure("parse_error", str(exc)) from exc
    depth = tree_depth(tree)
    if depth > max_depth:
        raise ParseFailure("parse_error", f"ast_too_deep ({depth} > {max_depth})")
    return ParsedFile(
        path=sf.path,
        language=sf.language,
        tree=tree,
        source=source,
        has_syntax_errors=tree.root_node.has_error,
    )


def walk(node: Node, deadline: Deadline | None = None) -> Iterator[Node]:
    """Iterative pre-order traversal."""
    cursor = node.walk()
    while True:
        if deadline is not None:
            deadline.check()
        yield cursor.node  # type: ignore[misc]
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def enclosing_symbol(node: Node, source: bytes) -> str:
    """Dotted name of the enclosing function/class chain, or ``""`` at module level."""
    names: list[str] = []
    current: Node | None = node.parent
    while current is not None:
        if current.type in _SYMBOL_NODE_TYPES:
            name = current.child_by_field_name("name")
            if name is not None:
                names.append(node_text(name, source))
        current = current.parent
    return ".".join(reversed(names))
