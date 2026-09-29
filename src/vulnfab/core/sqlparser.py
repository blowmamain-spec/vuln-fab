"""SQL parsing behind a narrow interface.

Only this module may import ``pglast`` (GPL-3.0-or-later). If the project licence ever needs to
change, swap the implementation of :class:`SqlParser` here and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import pglast
from pglast.parser import ParseError


class SqlParseError(Exception):
    """The SQL could not be parsed."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


@dataclass(frozen=True)
class Statement:
    node: Any  # pglast AST node (parser-specific)
    kind: str  # node class name, e.g. "CreateStmt"
    line: int  # 1-based line where the statement starts
    end_line: int
    sql: str


@dataclass(frozen=True)
class PlFunction:
    raw: dict[str, Any]  # parse_plpgsql output for one function
    line: int = 1


@dataclass(frozen=True)
class ParseIssue:
    line: int
    message: str
    sql: str  # the chunk that failed (truncated)


@dataclass(frozen=True)
class LenientResult:
    statements: list[Statement]
    issues: list[ParseIssue]


class SqlParser(Protocol):
    def parse(self, sql: str) -> list[Statement]: ...

    def parse_lenient(self, sql: str) -> LenientResult: ...

    def parse_plpgsql(self, sql: str) -> list[PlFunction]: ...


class PglastParser:
    """SqlParser backed by pglast (the actual PostgreSQL parser)."""

    def parse(self, sql: str) -> list[Statement]:
        try:
            raw = pglast.parse_sql(sql)
        except ParseError as exc:
            raise SqlParseError(str(exc), _line_of(sql, _error_index(str(exc)))) from exc
        out: list[Statement] = []
        for rs in raw:
            start = rs.stmt_location or 0
            length = rs.stmt_len or (len(sql) - start)
            text = sql[start : start + length]
            lead = len(text) - len(text.lstrip())
            begin = start + lead
            stripped = text.strip()
            out.append(
                Statement(
                    node=rs.stmt,
                    kind=type(rs.stmt).__name__,
                    line=_line_of(sql, begin),
                    end_line=_line_of(sql, begin + max(len(stripped) - 1, 0)),
                    sql=stripped,
                )
            )
        return out

    def parse_lenient(self, sql: str) -> LenientResult:
        """Parse as much as possible: a bad statement becomes an issue, not a failure.

        psql meta-commands (lines starting with a backslash) are blanked out first. If the whole
        text parses, the result is identical to :meth:`parse`; otherwise the text is split into
        top-level statements (dollar-quote and comment aware) and each chunk is parsed alone.
        """
        cleaned = strip_psql_meta(sql)
        try:
            return LenientResult(self.parse(cleaned), [])
        except SqlParseError:
            pass
        statements: list[Statement] = []
        issues: list[ParseIssue] = []
        for offset, chunk in split_statements(cleaned):
            if not chunk.strip():
                continue
            base_line = _line_of(cleaned, offset) - 1
            try:
                for st in self.parse(chunk):
                    statements.append(
                        Statement(
                            node=st.node,
                            kind=st.kind,
                            line=st.line + base_line,
                            end_line=st.end_line + base_line,
                            sql=st.sql,
                        )
                    )
            except SqlParseError as exc:
                lead = len(chunk) - len(chunk.lstrip())
                issues.append(
                    ParseIssue(
                        line=_line_of(cleaned, offset + lead),
                        message=str(exc),
                        sql=chunk.strip()[:200],
                    )
                )
        return LenientResult(statements, issues)

    def parse_plpgsql(self, sql: str) -> list[PlFunction]:
        try:
            parsed = pglast.parse_plpgsql(sql)
        except ParseError as exc:
            raise SqlParseError(str(exc), _line_of(sql, _error_index(str(exc)))) from exc
        return [PlFunction(raw=item) for item in parsed]


def _line_of(sql: str, index: int) -> int:
    return sql.count("\n", 0, max(index, 0)) + 1


def _error_index(message: str) -> int:
    marker = "at index "
    pos = message.rfind(marker)
    if pos < 0:
        return 0
    digits = ""
    for ch in message[pos + len(marker) :]:
        if not ch.isdigit():
            break
        digits += ch
    return int(digits) if digits else 0


def strip_psql_meta(sql: str) -> str:
    """Blank out psql meta-command lines (``\\set``, ``\\c``, ...) keeping line numbers."""
    return "\n".join("" if line.lstrip().startswith("\\") else line for line in sql.split("\n"))


def split_statements(sql: str) -> list[tuple[int, str]]:
    """Split on top-level semicolons, honouring quotes, comments and dollar-quoting.

    Returns ``(start_offset, text)`` pairs; the trailing semicolon is included in each chunk.
    """
    chunks: list[tuple[int, str]] = []
    n = len(sql)
    i = 0
    start = 0
    while i < n:
        ch = sql[i]
        if ch == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
        elif ch == "/" and sql.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if sql.startswith("/*", i):
                    depth += 1
                    i += 2
                elif sql.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif ch == "'":
            i = _skip_quoted(sql, i, "'", backslash=sql[max(i - 1, 0)] in "eE")
        elif ch == '"':
            i = _skip_quoted(sql, i, '"')
        elif ch == "$":
            tag = _dollar_tag(sql, i)
            if tag is None:
                i += 1
            else:
                j = sql.find(tag, i + len(tag))
                i = n if j < 0 else j + len(tag)
        elif ch == ";":
            chunks.append((start, sql[start : i + 1]))
            i += 1
            start = i
        else:
            i += 1
    if start < n:
        chunks.append((start, sql[start:]))
    return chunks


def _skip_quoted(sql: str, i: int, quote: str, backslash: bool = False) -> int:
    n = len(sql)
    i += 1
    while i < n:
        if backslash and sql[i] == "\\":
            i += 2
            continue
        if sql[i] == quote:
            if i + 1 < n and sql[i + 1] == quote:
                i += 2
                continue
            return i + 1
        i += 1
    return n


def _dollar_tag(sql: str, i: int) -> str | None:
    """Return ``$tag$`` if a dollar-quote opens at ``i`` (not a ``$1`` parameter)."""
    j = i + 1
    n = len(sql)
    while j < n and (sql[j].isalnum() or sql[j] == "_"):
        j += 1
    if j < n and sql[j] == "$":
        tag = sql[i : j + 1]
        if len(tag) == 2 or not tag[1].isdigit():
            return tag
    return None
