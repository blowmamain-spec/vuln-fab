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


class SqlParser(Protocol):
    def parse(self, sql: str) -> list[Statement]: ...

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
