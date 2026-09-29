from dataclasses import dataclass

import pytest

from vulnfab.core.safeexpr import UnsafeExpression, compile_expression, evaluate


@dataclass
class Table:
    schema: str
    name: str
    rls_enabled: bool
    columns: list[str]


T = Table("public", "notes", False, ["id", "user_id"])


def test_condition_from_plan() -> None:
    expr = "table.schema == 'public' and not table.rls_enabled"
    assert evaluate(expr, table=T) is True
    assert evaluate(expr, table=Table("private", "x", False, [])) is False


def test_membership_and_literals() -> None:
    assert evaluate("'user_id' in table.columns", table=T)
    assert evaluate("table.schema in ('public', 'auth')", table=T)
    assert not evaluate("table.name not in ['notes']", table=T)
    assert evaluate("table.name != 'x' or False", table=T)


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')",
        "table.__class__",
        "table.__dict__",
        "table._private",
        "().__class__.__mro__",
        "open('/etc/passwd')",
        "table.name.upper()",
        "[x for x in table.columns]",
        "lambda: 1",
        "table.columns[0]",
        "(y := 1)",
        "f'{table.name}'",
        "9 ** 9 ** 9",
        "table.name + 'x'",
        "-1",
        "eval('1')",
        "unknown_name",
        "{'a': 1}",
        "[table]",
        "table if True else table",
    ],
)
def test_rejects_unsafe_constructs(source: str) -> None:
    with pytest.raises(UnsafeExpression):
        compile_expression(source, {"table"})


def test_rejects_syntax_errors_and_size() -> None:
    with pytest.raises(UnsafeExpression):
        compile_expression("table.schema ==", {"table"})
    with pytest.raises(UnsafeExpression):
        compile_expression("table.name == '" + "a" * 600 + "'", {"table"})
    with pytest.raises(UnsafeExpression):
        compile_expression(" and ".join(["True"] * 200), {"table"})


def test_context_names_are_checked() -> None:
    fn = compile_expression("a == b", {"a", "b"})
    assert fn(a=1, b=1) is True
    with pytest.raises(TypeError):
        fn(a=1, b=1, c=2)


def test_no_builtins_leak() -> None:
    fn = compile_expression("table.name == 'notes'", {"table"})
    assert fn(table=T)
