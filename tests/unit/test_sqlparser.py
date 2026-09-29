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


def test_lenient_recovers_from_bad_statement() -> None:
    sql = "CREATE TABLE a (id int);\nCREATE TABL b;\nCREATE TABLE c (id int);\n"
    result = PglastParser().parse_lenient(sql)
    assert [s.kind for s in result.statements] == ["CreateStmt", "CreateStmt"]
    assert [s.line for s in result.statements] == [1, 3]
    assert len(result.issues) == 1
    assert result.issues[0].line == 2


def test_lenient_ignores_psql_meta_and_dollar_quotes() -> None:
    sql = (
        "\\set pgpass `echo x`\n"
        "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END; $$ LANGUAGE plpgsql;\n"
        "ALTER USER u WITH PASSWORD :'pgpass';\n"
        "CREATE TABLE t (id int);\n"
    )
    result = PglastParser().parse_lenient(sql)
    assert [s.kind for s in result.statements] == ["CreateFunctionStmt", "CreateStmt"]
    assert [i.line for i in result.issues] == [3]
    assert result.statements[0].line == 2


def test_split_respects_strings_comments_and_dollars() -> None:
    from vulnfab.core.sqlparser import split_statements

    sql = "select ';'; -- a;b\nselect $q$;$q$; /* ; */ select 1;"
    parts = [c.strip() for _, c in split_statements(sql)]
    assert parts == ["select ';';", "-- a;b\nselect $q$;$q$;", "/* ; */ select 1;"]
