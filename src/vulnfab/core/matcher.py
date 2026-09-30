"""Snippet-pattern matcher on top of tree-sitter (WP-2.3; design validated by spike S2).

A pattern is a code snippet in the target language. ``$NAME`` (upper case) binds any subtree;
a bare ``...`` matches zero or more sibling elements (arguments, statements, ...). Patterns are
parsed with the same grammar as the target, so structure is compared node by node.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from tree_sitter import Node, Tree

from vulnfab.core.parsing import Deadline, line_of, parser_for, walk
from vulnfab.core.rules import PatternRule, WhereClause

ELLIPSIS = "__ELLIPSIS__"
MV_PREFIX = "__MV_"
_MV_TEXT = re.compile(r"^\$?__MV_([A-Z][A-Z0-9_]*)$")
_MV_SOURCE = re.compile(r"\$([A-Z_][A-Z0-9_]*)")
_ELLIPSIS_SOURCE = re.compile(r"\.\.\.(?![\w$])")
_PHP_SUPERGLOBALS = frozenset(
    {"_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES", "_SESSION", "_ENV", "GLOBALS"}
)
_WRAPPER_TYPES = frozenset({"module", "program", "expression_statement", "php_tag", "text"})
_SKIP_TOKENS = frozenset({",", ";"})
_MAX_PATTERN_STEPS = 200_000
# Wrappers that do not change what an expression *is*: `await x`, `x!`, `x as T`, `(x)`.
_TRANSPARENT_WRAPPERS = frozenset(
    {
        "await_expression", "non_null_expression", "as_expression", "satisfies_expression",
        "type_assertion", "parenthesized_expression",
    }
)  # fmt: skip
# Type-only syntax: ignored on the target side unless the pattern itself spells it out.
_TYPE_ONLY = frozenset({"type_arguments", "type_annotation"})


class PatternError(ValueError):
    """The pattern snippet is invalid."""


# --- pattern compilation --------------------------------------------------------------------


def _replace_outside_strings(text: str, fn) -> str:  # type: ignore[no-untyped-def]
    out: list[str] = []
    i, n, start = 0, len(text), 0
    while i < n:
        ch = text[i]
        if ch in "'\"`":
            out.append(fn(text[start:i]))
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = start = j + 1
        else:
            i += 1
    out.append(fn(text[start:]))
    return "".join(out)


def _prepare(language: str, snippet: str) -> str:
    def swap(chunk: str) -> str:
        chunk = _ELLIPSIS_SOURCE.sub(ELLIPSIS, chunk)

        def mv(m: re.Match[str]) -> str:
            name = m.group(1)
            if language == "php" and name in _PHP_SUPERGLOBALS:
                return m.group(0)
            return ("$" if language == "php" else "") + MV_PREFIX + name

        return _MV_SOURCE.sub(mv, chunk)

    prepared = _replace_outside_strings(snippet.strip(), swap)
    if language == "php":
        if not prepared.endswith((";", "}")):
            prepared += ";"
        prepared = "<?php " + prepared
    return prepared


@dataclass
class CompiledPattern:
    language: str
    snippet: str
    root: Node
    tree: Tree  # keeps the pattern tree alive

    @property
    def root_type(self) -> str:
        return self.root.type


def _first_error(node: Node) -> Node | None:
    for n in walk(node):
        if n.type == "ERROR" or n.is_missing:
            return n
    return None


def _unwrap(root: Node) -> Node:
    node = root
    while node.type in _WRAPPER_TYPES:
        kids = [c for c in node.children if c.type not in _WRAPPER_TYPES - {"expression_statement"}]
        kids = [c for c in kids if c.type not in _SKIP_TOKENS and c.type != "comment"]
        if len(kids) != 1:
            raise PatternError("pattern must be a single expression or statement")
        node = kids[0]
    return node


def compile_pattern(language: str, snippet: str) -> CompiledPattern:
    parser = parser_for(language)
    if parser is None:
        raise PatternError(f"language {language!r} has no parser")
    prepared = _prepare(language, snippet)
    prepared_bytes = prepared.encode("utf-8")
    tree = parser.parse(prepared_bytes)
    bad = _first_error(tree.root_node)
    if bad is not None:
        line = line_of(prepared_bytes, bad.start_byte)
        raise PatternError(f"pattern is not valid {language} code near line {line}: {snippet!r}")
    return CompiledPattern(language, snippet, _unwrap(tree.root_node), tree)


# --- matching -------------------------------------------------------------------------------

Env = dict[str, Node]


def _t(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def _sig(node: Node) -> list[Node]:
    return [c for c in node.children if c.type != "comment" and c.type not in _SKIP_TOKENS]


def _is_ellipsis(node: Node) -> bool:
    return _t(node).rstrip(";").strip() == ELLIPSIS


def _metavar(node: Node) -> str | None:
    m = _MV_TEXT.match(_t(node))
    return m.group(1) if m else None


_STRING_TYPES = frozenset({"string", "encapsed_string", "string_literal"})
_STRING_PREFIX = re.compile(r"^[rRbBuUfF]{0,2}")


def string_value(node: Node) -> str | None:
    """Inner text of a plain (non-interpolated) string literal, else ``None``."""
    if node.type not in _STRING_TYPES:
        return None
    if any(
        c.type in {"interpolation", "template_substitution", "variable_name"} for c in node.children
    ):  # noqa: E501
        return None
    text = _t(node)
    m = _STRING_PREFIX.match(text)
    prefix = m.group(0) if m else ""
    if "f" in prefix.lower():
        return None
    body = text[len(prefix) :]
    for quote in ('"""', "'''", '"', "'"):
        if body.startswith(quote) and body.endswith(quote) and len(body) >= 2 * len(quote):
            return body[len(quote) : -len(quote)]
    return None


def _normalise(text: str) -> str:
    return " ".join(text.split())


class _Budget:
    def __init__(self, steps: int = _MAX_PATTERN_STEPS) -> None:
        self.steps = steps

    def spend(self) -> bool:
        self.steps -= 1
        return self.steps >= 0


def _wrapped_expression(node: Node) -> Node | None:
    named = [c for c in node.children if c.is_named and c.type != "comment"]
    if node.type == "type_assertion":  # <T>expr -> the expression is the last named child
        return named[-1] if named else None
    if node.type in ("as_expression", "satisfies_expression"):
        return named[0] if named else None
    return named[0] if len(named) == 1 else None


def _match(p: Node, t: Node, env: Env, budget: _Budget) -> Env | None:
    if not budget.spend():
        return None
    name = _metavar(p)
    if name is not None:
        bound = env.get(name)
        if bound is None:
            new = dict(env)
            new[name] = t
            return new
        return env if _normalise(_t(bound)) == _normalise(_t(t)) else None
    if t.type in _TRANSPARENT_WRAPPERS and p.type != t.type:
        inner = _wrapped_expression(t)
        if inner is not None:
            return _match(p, inner, env, budget)
    if p.type != t.type:
        return None
    pv, tv = string_value(p), string_value(t)
    if pv is not None and tv is not None:
        return env if pv == tv else None
    pk = _sig(p)
    if not pk:
        return env if _t(p) == _t(t) else None
    tk = _sig(t)
    if not any(c.type in _TYPE_ONLY for c in pk):
        tk = [c for c in tk if c.type not in _TYPE_ONLY]
    return _match_seq(pk, tk, env, budget)


def _match_seq(pk: list[Node], tk: list[Node], env: Env, budget: _Budget) -> Env | None:
    if not pk:
        return env if not tk else None
    head = pk[0]
    if _is_ellipsis(head):
        rest = pk[1:]
        for skip in range(len(tk) + 1):
            result = _match_seq(rest, tk[skip:], env, budget)
            if result is not None:
                return result
            if budget.steps < 0:
                return None
        return None
    if not tk:
        return None
    matched = _match(head, tk[0], env, budget)
    if matched is None:
        return None
    return _match_seq(pk[1:], tk[1:], matched, budget)


@dataclass(frozen=True)
class Match:
    node: Node
    env: Env = field(default_factory=dict)


def match_at(pattern: CompiledPattern, node: Node, env: Env | None = None) -> Env | None:
    if node.type != pattern.root_type:
        return None
    return _match(pattern.root, node, dict(env or {}), _Budget())


# --- where clauses --------------------------------------------------------------------------

_LITERAL_TYPES = frozenset(
    {
        "integer", "float", "true", "false", "none", "null", "number", "boolean",
        "integer_literal", "float_literal", "nowdoc", "undefined",
    }
)  # fmt: skip
_IDENTIFIER_TYPES = frozenset(
    {"identifier", "property_identifier", "variable_name", "name", "shorthand_property_identifier"}
)
_CONCAT_OPERATORS = {
    "python": {"+", "%"},
    "javascript": {"+"},
    "typescript": {"+"},
    "tsx": {"+"},
    "php": {"."},
}  # noqa: E501
_INTERPOLATION_TYPES = frozenset({"interpolation", "template_substitution"})


def is_literal(node: Node) -> bool:
    if node.type in _LITERAL_TYPES:
        return True
    if node.type in _STRING_TYPES or node.type in {"template_string", "concatenated_string"}:
        return not _has_interpolation(node)
    if node.type == "parenthesized_expression":
        inner = _sig(node)
        return len(inner) == 3 and is_literal(inner[1])
    return False


def _has_interpolation(node: Node) -> bool:
    for n in walk(node):
        if n.type in _INTERPOLATION_TYPES:
            return True
        if n.type == "variable_name" and node.type == "encapsed_string":
            return True
        if (
            n.type in {"member_expression", "subscript_expression"}
            and node.type == "encapsed_string"
        ):  # noqa: E501
            return True
    return False


def is_dynamic_string(node: Node, language: str) -> bool:
    """f-string / template literal / concatenation / format() with any non-literal part."""
    if node.type in _STRING_TYPES or node.type in {"template_string", "concatenated_string"}:
        return _has_interpolation(node)
    if node.type in {"binary_operator", "binary_expression"}:
        op = next((c for c in node.children if not c.is_named), None)
        if op is not None and _t(op) in _CONCAT_OPERATORS.get(language, {"+"}):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            operands = [x for x in (left, right) if x is not None]
            return any(
                is_dynamic_string(o, language) or not is_literal(o) for o in operands
            ) and not all(is_literal(o) for o in operands)
    if node.type == "call" and language == "python":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "attribute":
            attr = fn.child_by_field_name("attribute")
            obj = fn.child_by_field_name("object")
            if (
                attr is not None
                and _t(attr) == "format"
                and obj is not None
                and obj.type == "string"
            ):  # noqa: E501
                return True
    if node.type == "parenthesized_expression":
        inner = _sig(node)
        return len(inner) == 3 and is_dynamic_string(inner[1], language)
    return False


_TRANSPARENT = frozenset({"argument", "expression_statement"})


def _core(node: Node) -> Node:
    """Strip grammar wrappers that carry no meaning (e.g. PHP ``argument``)."""
    while node.type in _TRANSPARENT:
        named = [c for c in node.children if c.is_named]
        if len(named) != 1:
            break
        node = named[0]
    return node


# Interpolated values that are safe to put into HTML: escaped/sanitized/numeric.
_SAFE_PART = re.compile(
    r"(?is)^\s*(?:[\w$.]+\.)?(?:esc\w*|escape\w*|sanitiz\w*|encode\w*|purify\w*|safe\w*|"
    r"clean\w*|number|parseint|parsefloat|tofixed|tolocale\w*|json\.stringify)\s*\("
    r"|^\s*\d+(?:\.\d+)?\s*$|^\s*[\w$.]+\.(?:length|size|count)\s*$"
    r"|^\s*(?:int|float|bool|len|intval|floatval|abs|round|uuid\w*)\s*\("
)


def _interpolated_parts(node: Node) -> list[Node]:
    """Non-literal pieces of a built string: template literal, f-string, ``%``/``.format``,
    PHP interpolation and ``+``/``.`` concatenation."""
    if node.type == "template_string":
        parts: list[Node] = []
        for child in node.children:
            if child.type == "template_substitution":
                parts.extend(c for c in child.children if c.is_named)
        return parts
    if node.type == "string":  # python f-string
        return [
            inner
            for child in node.children
            if child.type == "interpolation"
            for inner in child.children[:2]
            if inner.is_named
        ][:16]
    if node.type == "encapsed_string":  # php "...$x..." / "{$x->y}"
        return [c for c in node.children if c.is_named and c.type != "string_content"]
    if node.type == "call":  # python "...{}".format(x)
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is not None and fn.type == "attribute" and args is not None:
            attr = fn.child_by_field_name("attribute")
            obj = fn.child_by_field_name("object")
            if (
                attr is not None
                and _t(attr) == "format"
                and obj is not None
                and obj.type == "string"
            ):
                out: list[Node] = []
                for a in args.children:
                    if a.type == "keyword_argument":
                        value = a.child_by_field_name("value")
                        if value is not None:
                            out.append(value)
                    elif a.is_named:
                        out.append(a)
                return [x for x in out if not is_literal(x)]
        return []
    if node.type == "parenthesized_expression":
        inner = [c for c in node.children if c.is_named]
        return _interpolated_parts(inner[0]) if inner else []
    if node.type in ("binary_expression", "binary_operator"):
        op = next((c for c in node.children if not c.is_named), None)
        if op is None:
            return []
        symbol = _t(op)
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if symbol == "%" and node.type == "binary_operator" and right is not None:
            # python "..." % value | "..." % (a, b)
            items = [c for c in right.children if c.is_named] if right.type == "tuple" else [right]
            return [x for x in items if not is_literal(x)]
        if symbol in ("+", "."):
            out = []
            for side in (left, right):
                if side is None or is_literal(side):
                    continue
                nested = _interpolated_parts(side)
                out.extend(
                    nested
                    if nested
                    or side.type
                    in ("template_string", "binary_expression", "binary_operator", "string")
                    else [side]
                )
            return out
    return []


def _callback_results(fn: Node) -> list[Node] | None:
    """Returned expressions of an arrow/function callback (``None`` if not statically known)."""
    body = fn.child_by_field_name("body")
    if body is None:
        return None
    if body.type != "statement_block":
        return [body]
    results: list[Node] = []
    stack = list(body.children)
    while stack:
        node = stack.pop()
        if node.type == "return_statement":
            values = [c for c in node.children if c.is_named]
            if not values:
                return None
            results.append(values[0])
        elif node.type not in ("arrow_function", "function_expression", "function_declaration"):
            stack.extend(node.children)
    return results or None


def _part_is_safe(node: Node, depth: int = 0) -> bool:
    """Is an interpolated value visibly escaped, numeric, or built only from safe pieces?"""
    if depth > 6:
        return False
    text = _t(node)
    if _SAFE_PART.match(text) or is_literal(node):
        return True
    kind = node.type
    if kind == "parenthesized_expression":
        inner = [c for c in node.children if c.is_named]
        return bool(inner) and _part_is_safe(inner[0], depth + 1)
    if kind == "template_string" or (kind in ("binary_expression",) and _interpolated_parts(node)):
        return not any(not _part_is_safe(p, depth + 1) for p in _interpolated_parts(node))
    if kind == "ternary_expression" or kind == "conditional_expression":
        branches = [
            node.child_by_field_name("consequence"),
            node.child_by_field_name("alternative"),
        ]
        return all(b is not None and _part_is_safe(b, depth + 1) for b in branches)
    if kind == "binary_expression":
        op = next((c for c in node.children if not c.is_named), None)
        symbol = _t(op) if op is not None else ""
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if symbol in ("||", "??") and left is not None and right is not None:
            return _part_is_safe(left, depth + 1) and _part_is_safe(right, depth + 1)
        if symbol == "&&" and right is not None:  # `cond && escapeHtml(x)`
            return _part_is_safe(right, depth + 1)
        return False
    if kind == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            recv = fn.child_by_field_name("object")
            if prop is not None and _t(prop) == "join" and recv is not None:
                return _mapped_html_is_safe(recv, depth + 1)
    return False


def _mapped_html_is_safe(node: Node, depth: int) -> bool:
    """``items.map(x => `<li>${escapeHtml(x)}</li>`)``: safe when the callback builds safe HTML."""
    if node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if fn is None or args is None or fn.type != "member_expression":
        return False
    prop = fn.child_by_field_name("property")
    if prop is None or _t(prop) != "map":
        return False
    callbacks = [c for c in args.children if c.type in ("arrow_function", "function_expression")]
    if len(callbacks) != 1:
        return False
    results = _callback_results(callbacks[0])
    return results is not None and all(_part_is_safe(r, depth) for r in results)


def has_unsafe_interpolation(node: Node) -> bool:
    """A built string with at least one interpolated value that is not visibly escaped."""
    if node.type == "call_expression" and _is_map_join(node):
        return not _part_is_safe(node)
    return any(not _part_is_safe(part) for part in _interpolated_parts(node))


def _is_map_join(node: Node) -> bool:
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return False
    prop, recv = fn.child_by_field_name("property"), fn.child_by_field_name("object")
    if prop is None or _t(prop) != "join" or recv is None or recv.type != "call_expression":
        return False
    inner = recv.child_by_field_name("function")
    name = inner.child_by_field_name("property") if inner is not None else None
    return name is not None and _t(name) == "map"


def check_where(clause: WhereClause, env: Env, language: str) -> bool:
    bound = env.get(clause.metavariable)
    if bound is None:
        return False
    node = _core(bound)
    kind = clause.kind
    if kind == "literal":
        return is_literal(node)
    if kind == "not_literal":
        return not is_literal(node)
    if kind == "identifier":
        return node.type in _IDENTIFIER_TYPES
    if kind == "fstring_or_concat":
        return is_dynamic_string(node, language)
    if kind == "not_fstring_or_concat":
        return not is_dynamic_string(node, language)
    if kind == "unsafe_interpolation":
        return has_unsafe_interpolation(node)
    assert clause.regex is not None
    found = re.search(clause.regex, _t(node)) is not None
    return found if kind == "regex" else not found


# --- rule compilation and execution ---------------------------------------------------------


@dataclass
class CompiledRule:
    rule: PatternRule
    anchors: dict[str, list[CompiledPattern]]
    pattern_not: dict[str, list[CompiledPattern]]
    inside: dict[str, list[CompiledPattern]]
    not_inside: dict[str, list[CompiledPattern]]


def compile_rule(rule: PatternRule) -> CompiledRule:
    def build(snippets: list[str]) -> dict[str, list[CompiledPattern]]:
        out: dict[str, list[CompiledPattern]] = {}
        for lang in rule.languages:
            try:
                out[lang] = [compile_pattern(lang, s) for s in snippets]
            except PatternError as exc:
                raise PatternError(f"rule {rule.id!r} ({lang}): {exc}") from exc
        return out

    return CompiledRule(
        rule=rule,
        anchors=build(rule.anchors),
        pattern_not=build(rule.pattern_not),
        inside=build(rule.pattern_inside),
        not_inside=build(rule.pattern_not_inside),
    )


class FileIndex:
    """Nodes of one parsed file grouped by type (built once, shared by all rules)."""

    def __init__(self, tree: Tree, deadline: Deadline | None = None) -> None:
        self.by_type: dict[str, list[Node]] = {}
        for node in walk(tree.root_node, deadline):
            self.by_type.setdefault(node.type, []).append(node)


def _ancestors(node: Node) -> Iterator[Node]:
    current = node.parent
    while current is not None:
        yield current
        current = current.parent


def run_rule(crule: CompiledRule, language: str, index: FileIndex) -> list[Match]:
    anchors = crule.anchors.get(language)
    if not anchors:
        return []
    rule = crule.rule
    not_patterns = crule.pattern_not.get(language, [])
    inside = crule.inside.get(language, [])
    not_inside = crule.not_inside.get(language, [])
    found: dict[tuple[int, int, str], Match] = {}
    for anchor in anchors:
        for node in index.by_type.get(anchor.root_type, []):
            env = match_at(anchor, node)
            if env is None:
                continue
            if any(match_at(p, node, env) is not None for p in not_patterns):
                continue
            if inside and not any(
                match_at(p, a, env) is not None for a in _ancestors(node) for p in inside
            ):
                continue
            if any(match_at(p, a, env) is not None for a in _ancestors(node) for p in not_inside):
                continue
            if not all(check_where(w, env, language) for w in rule.where):
                continue
            found[(node.start_byte, node.end_byte, rule.id)] = Match(node, env)
    return sorted(found.values(), key=lambda m: (m.node.start_byte, m.node.end_byte))
