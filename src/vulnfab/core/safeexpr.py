"""Safe expression evaluator for rule ``condition`` strings (decision D6).

Only attribute access on the supplied context, comparisons, boolean logic and literals are
allowed. No calls, no subscripts, no comprehensions, no arithmetic, no private attributes.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from typing import Any

MAX_EXPR_LENGTH = 500
MAX_NODES = 100


class UnsafeExpression(ValueError):
    """The expression uses a construct that is not allowed."""


_ALLOWED_CMP = (ast.Eq, ast.NotEq, ast.In, ast.NotIn, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_ALLOWED_CONSTANTS = (str, int, float, bool, type(None))


def _validate(node: ast.AST, names: frozenset[str]) -> None:
    if isinstance(node, ast.Expression):
        _validate(node.body, names)
    elif isinstance(node, ast.BoolOp):
        for value in node.values:
            _validate(value, names)
    elif isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, ast.Not):
            raise UnsafeExpression("only 'not' is allowed as a unary operator")
        _validate(node.operand, names)
    elif isinstance(node, ast.Compare):
        if not all(isinstance(op, _ALLOWED_CMP) for op in node.ops):
            raise UnsafeExpression("comparison operator not allowed")
        _validate(node.left, names)
        for comparator in node.comparators:
            _validate(comparator, names)
    elif isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise UnsafeExpression(f"access to private attribute {node.attr!r} is not allowed")
        _validate(node.value, names)
    elif isinstance(node, ast.Name):
        if node.id not in names:
            raise UnsafeExpression(f"unknown name {node.id!r}")
    elif isinstance(node, ast.Constant):
        if not isinstance(node.value, _ALLOWED_CONSTANTS):
            raise UnsafeExpression("constant type not allowed")
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for element in node.elts:
            if not isinstance(element, ast.Constant):
                raise UnsafeExpression("collections may contain literals only")
            _validate(element, names)
    else:
        raise UnsafeExpression(f"{type(node).__name__} is not allowed")


def compile_expression(source: str, names: set[str] | frozenset[str]) -> Callable[..., Any]:
    """Compile ``source`` into a function taking the context as keyword arguments."""
    if len(source) > MAX_EXPR_LENGTH:
        raise UnsafeExpression(f"expression longer than {MAX_EXPR_LENGTH} characters")
    try:
        tree = ast.parse(source.strip(), mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression(f"syntax error: {exc.msg}") from exc
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        raise UnsafeExpression("expression too complex")
    allowed = frozenset(names)
    _validate(tree, allowed)
    code = compile(tree, "<rule-condition>", "eval")

    def run(**context: Mapping[str, Any] | Any) -> Any:
        unknown = set(context) - allowed
        if unknown:
            raise TypeError(f"unexpected context names: {sorted(unknown)}")
        return eval(code, {"__builtins__": {}}, dict(context))  # noqa: S307 - validated AST only

    return run


def evaluate(source: str, **context: Any) -> Any:
    return compile_expression(source, set(context))(**context)
