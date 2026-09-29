"""Static reading of Django ``settings.py`` and ``models.py`` (never executes project code)."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Dynamic:
    """A value that is not a literal (environment lookup, computed, conditional...)."""

    source: str = ""

    def __repr__(self) -> str:
        return f"<dynamic {self.source}>" if self.source else "<dynamic>"


def literal(node: ast.AST) -> Any:
    """Evaluate a settings value if it is built only from literals, else :class:`Dynamic`."""
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        pass
    if isinstance(node, (ast.List, ast.Tuple)):
        items = [literal(e) for e in node.elts]
        return items if isinstance(node, ast.List) else tuple(items)
    if isinstance(node, ast.Dict):
        return {
            (literal(k) if k is not None else Dynamic("**")): literal(v)
            for k, v in zip(node.keys, node.values, strict=True)
        }
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = literal(node.left), literal(node.right)
        if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
            return [*left, *right]
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001 - unparse can fail on odd nodes; the text is informational
        text = ""
    return Dynamic(text[:80])


def is_dynamic(value: Any) -> bool:
    if isinstance(value, Dynamic):
        return True
    if isinstance(value, (list, tuple)):
        return any(is_dynamic(v) for v in value)
    if isinstance(value, dict):
        return any(is_dynamic(v) for v in value.values())
    return False


@dataclass
class SettingsRead:
    values: dict[str, Any]
    lines: dict[str, int]
    conditional: set[str]  # assigned inside if/try/for/with (value may not apply everywhere)
    mutated: set[str]  # changed by +=, .append(), .update(), [k] = ...


def read_settings(text: str) -> SettingsRead | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    out = SettingsRead({}, {}, set(), set())

    def visit(body: list[ast.stmt], conditional: bool) -> None:
        for node in body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        out.values[target.id] = literal(node.value)
                        out.lines.setdefault(target.id, node.lineno)
                        out.lines[target.id] = node.lineno
                        if conditional:
                            out.conditional.add(target.id)
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        out.mutated.add(target.value.id)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id.isupper() and node.value:
                    out.values[node.target.id] = literal(node.value)
                    out.lines[node.target.id] = node.lineno
                    if conditional:
                        out.conditional.add(node.target.id)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                out.mutated.add(node.target.id)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    out.mutated.add(func.value.id)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                for attr in ("body", "orelse", "finalbody"):
                    visit(getattr(node, attr, []) or [], True)
                for handler in getattr(node, "handlers", []) or []:
                    visit(handler.body, True)

    visit(tree.body, False)
    return out


# --- models ----------------------------------------------------------------------------------


@dataclass
class ModelField:
    name: str
    kind: str  # CharField, ForeignKey, ...
    line: int
    null: bool = False
    unique: bool = False
    target: str | None = None  # relation target as written


@dataclass
class ModelClass:
    name: str
    bases: list[str]
    line: int
    end_line: int
    fields: list[ModelField]
    abstract: bool = False


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _target(call: ast.Call) -> str | None:
    node: ast.AST | None = call.args[0] if call.args else _kw(call, "to")
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return _dotted(node) or None


RELATION_FIELDS = {"ForeignKey", "OneToOneField", "ManyToManyField"}


def read_models(text: str) -> list[ModelClass] | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    classes: list[ModelClass] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        fields: list[ModelField] = []
        abstract = False
        for item in node.body:
            if isinstance(item, ast.ClassDef) and item.name == "Meta":
                for meta in item.body:
                    if (
                        isinstance(meta, ast.Assign)
                        and any(
                            isinstance(t, ast.Name) and t.id == "abstract" for t in meta.targets
                        )
                        and _true(meta.value)
                    ):
                        abstract = True
            if not isinstance(item, ast.Assign) or not isinstance(item.value, ast.Call):
                continue
            kind = _dotted(item.value.func).rsplit(".", 1)[-1]
            if not kind.endswith("Field") and kind not in RELATION_FIELDS:
                continue
            for target in item.targets:
                if isinstance(target, ast.Name):
                    fields.append(
                        ModelField(
                            target.id,
                            kind,
                            item.lineno,
                            null=_true(_kw(item.value, "null")),
                            unique=_true(_kw(item.value, "unique"))
                            or _true(_kw(item.value, "primary_key")),
                            target=_target(item.value) if kind in RELATION_FIELDS else None,
                        )
                    )
        classes.append(
            ModelClass(
                node.name,
                [_dotted(b) for b in node.bases],
                node.lineno,
                node.end_lineno or node.lineno,
                fields,
                abstract,
            )
        )
    return classes
