import ast
from pathlib import Path

import pytest

from vulnfab.core.sqlparser import PglastParser, SqlParseError

SQL = """CREATE TABLE t (id int);

-- enable rls
ALTER TABLE t ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON t FOR SELECT TO anon
  USING (true);
"""


def test_parse_statements_with_lines() -> None:
    stmts = PglastParser().parse(SQL)
    assert [s.kind for s in stmts] == ["CreateStmt", "AlterTableStmt", "CreatePolicyStmt"]
    assert stmts[0].line == 1
    assert stmts[1].line == 4
    assert (stmts[2].line, stmts[2].end_line) == (5, 6)


def test_parse_error_reports_line() -> None:
    with pytest.raises(SqlParseError) as info:
        PglastParser().parse("SELECT 1;\nCREATE TABL x;")
    assert info.value.line == 2


def test_plpgsql_dynamic_execute_is_visible() -> None:
    fn = (
        "CREATE FUNCTION f(x text) RETURNS void AS $$ BEGIN "
        "EXECUTE 'select ' || x; END; $$ LANGUAGE plpgsql SECURITY DEFINER;"
    )
    funcs = PglastParser().parse_plpgsql(fn)
    assert len(funcs) == 1
    assert "PLpgSQL_stmt_dynexecute" in str(funcs[0].raw)


def test_only_sqlparser_imports_pglast() -> None:
    src = Path(__file__).resolve().parents[2] / "src" / "vulnfab"
    offenders = []
    for path in src.rglob("*.py"):
        if path.name == "sqlparser.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n == "pglast" or n.startswith("pglast.") for n in names):
                offenders.append(str(path))
    assert offenders == []
