"""Cross-check rules: relate code-level `DataAccess` facts to the Supabase schema model."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence, DataAccess, Table, TraceStep
from vulnfab.core.schemarules import CheckContext, SchemaHit
from vulnfab.plugins.supabase.access import AccessKind, effective_access

ANON_KEY_CLIENTS = frozenset({"anon", "user"})
OWNER_COLUMNS = frozenset(
    {"user_id", "owner_id", "created_by", "author_id", "profile_id", "account_id", "uid"}
)
REQUEST_VALUE = re.compile(
    r"\b(params|query|searchParams|req|request|body|slug|useParams|router\.query|event\.params)\b"
)
COMMANDS = {"select": ("select",), "insert": ("insert",), "update": ("update",),
            "delete": ("delete",), "upsert": ("insert", "update")}  # fmt: skip


def _table_for(ctx: CheckContext, access: DataAccess) -> Table | None:
    schema = access.schema or "public"
    return ctx.model.tables.get(f"{schema}.{access.table}")


def _code_trace(a: DataAccess, note: str) -> TraceStep:
    return TraceStep(a.file, a.line, "source", note)


def table_no_rls(ctx: CheckContext) -> Iterator[SchemaHit]:
    for a in ctx.facts:
        if a.op == "rpc" or a.client_kind == "service_role":
            continue
        table = _table_for(ctx, a)
        if table is None or table.rls_enabled:
            continue
        opened = [
            c for c in COMMANDS[a.op]
            if effective_access(table, "anon", c).kind is AccessKind.ALLOW
        ]  # fmt: skip
        if not opened:
            continue
        known = a.client_kind in ANON_KEY_CLIENTS
        yield SchemaHit(
            a.file,
            a.line,
            a.end_line or a.line,
            f"{table.qualified_name} is {'/'.join(opened)}ed through the public API by this code "
            f"({'anon key' if known else 'client of unknown key'}), but Row Level Security is off "
            "on that table: anyone holding the public key can do the same.",
            trace=(
                _code_trace(a, f"from('{a.table}').{a.op}(...)"),
                TraceStep(table.rls_file, table.rls_line, "schema", "RLS not enabled here"),
            ),
            symbol=f"{a.file}:{table.qualified_name}",
            confidence=None if known else Confidence.LOW,
        )


def _owner_filtered(a: DataAccess, table: Table) -> bool:
    owner_like = OWNER_COLUMNS | {c.name for c in table.columns if c.name.endswith("_user_id")}
    return any(col in owner_like for col in a.filter_columns)


def idor_eq_id(ctx: CheckContext) -> Iterator[SchemaHit]:
    for a in ctx.facts:
        if a.op not in ("select", "update", "delete"):
            continue
        by_id = [(c, v) for c, v in a.filters if c == "id" and REQUEST_VALUE.search(v)]
        if not by_id:
            continue
        table = _table_for(ctx, a)
        if table is None or _owner_filtered(a, table):
            continue
        if not any(c.name in OWNER_COLUMNS for c in table.columns):
            continue  # rows have no owner: nothing to enforce (reference data)
        if a.client_kind == "service_role":
            why = "the service_role client bypasses RLS, so only the query itself can restrict rows"
        else:
            access = effective_access(table, "authenticated", a.op)
            if access.kind is not AccessKind.ALLOW:
                continue  # owner-based or restricted policy: RLS enforces ownership
            why = (
                f"{table.qualified_name} allows any signed-in user to {a.op} every row "
                f"({access.reason})"
            )
        yield SchemaHit(
            a.file,
            a.line,
            a.end_line or a.line,
            f"Row of {table.qualified_name} is fetched by id from the request ({by_id[0][1]}) "
            f"without an owner filter, and {why}.",
            trace=(_code_trace(a, f"id = {by_id[0][1]}"),),
            symbol=f"{a.file}:{table.qualified_name}:id",
        )
