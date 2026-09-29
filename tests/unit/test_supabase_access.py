# ruff: noqa: E501
"""Truth table for effective_access (WP-3.4): >= 25 cases."""

import pytest

from vulnfab.plugins.supabase.access import Access, AccessKind, effective_access
from vulnfab.plugins.supabase.schema import SchemaBuilder

TABLE = "create table t (id int, user_id uuid, is_public bool);"
RLS = "alter table t enable row level security;"
A, D, C, U = AccessKind.ALLOW, AccessKind.DENY, AccessKind.CONDITIONAL, AccessKind.UNKNOWN


def acc(sql: str, role: str, command: str, *, rls: bool = True, table: str = TABLE) -> Access:
    b = SchemaBuilder()
    b.apply_file("m.sql", f"{table}\n{RLS if rls else ''}\n{sql}")
    name = "private.t" if "private." in table else "public.t"
    return effective_access(b.model.tables[name], role, command)


CASES = [
    # (description, sql, role, command, rls, expected kind)
    ("RLS off -> open", "", "anon", "select", False, A),
    ("RLS on, no policy -> deny", "", "anon", "select", True, D),
    (
        "select policy true, anon reads",
        "create policy p on t for select to anon using (true);",
        "anon",
        "select",
        True,
        A,
    ),
    (
        "select policy does not grant insert",
        "create policy p on t for select to anon using (true);",
        "anon",
        "insert",
        True,
        D,
    ),
    (
        "policy for authenticated does not open anon",
        "create policy p on t to authenticated using (true);",
        "anon",
        "select",
        True,
        D,
    ),
    (
        "policy for authenticated opens authenticated",
        "create policy p on t to authenticated using (true);",
        "authenticated",
        "select",
        True,
        A,
    ),
    (
        "policy without TO applies to everyone",
        "create policy p on t using (true);",
        "anon",
        "select",
        True,
        A,
    ),
    (
        "owner policy -> conditional",
        "create policy p on t to authenticated using ((select auth.uid()) = user_id);",
        "authenticated",
        "select",
        True,
        C,
    ),
    (
        "owner policy without subselect",
        "create policy p on t to authenticated using (auth.uid() = user_id);",
        "authenticated",
        "delete",
        True,
        C,
    ),
    (
        "owner policy, anon has no uid",
        "create policy p on t using (auth.uid() = user_id);",
        "anon",
        "select",
        True,
        D,
    ),
    (
        "FOR ALL using(true) covers insert",
        "create policy p on t for all using (true);",
        "authenticated",
        "insert",
        True,
        A,
    ),
    (
        "insert check(true)",
        "create policy p on t for insert with check (true);",
        "anon",
        "insert",
        True,
        A,
    ),
    (
        "insert policy does not grant select",
        "create policy p on t for insert with check (true);",
        "anon",
        "select",
        True,
        D,
    ),
    (
        "update needs both: check false",
        "create policy p on t for update using (true) with check (false);",
        "authenticated",
        "update",
        True,
        D,
    ),
    (
        "update using+check true",
        "create policy p on t for update using (true) with check (true);",
        "authenticated",
        "update",
        True,
        A,
    ),
    (
        "update owner",
        "create policy p on t for update using (auth.uid() = user_id);",
        "authenticated",
        "update",
        True,
        C,
    ),
    (
        "restrictive narrows permissive",
        "create policy a on t using (true); create policy r on t as restrictive using (auth.uid() = user_id);",
        "authenticated",
        "select",
        True,
        C,
    ),
    (
        "restrictive alone -> deny",
        "create policy r on t as restrictive using (true);",
        "authenticated",
        "select",
        True,
        D,
    ),
    (
        "OR of permissive: true wins",
        "create policy a on t using (auth.uid() = user_id); create policy b on t using (true);",
        "authenticated",
        "select",
        True,
        A,
    ),
    (
        "two conditional permissive",
        "create policy a on t using (auth.uid() = user_id); create policy b on t using (is_public);",
        "authenticated",
        "select",
        True,
        C,
    ),
    ("service_role bypasses RLS", "", "service_role", "delete", True, A),
    (
        "revoked grants deny even with RLS off",
        "revoke all on t from anon;",
        "anon",
        "select",
        False,
        D,
    ),
    (
        "partial grant: insert missing",
        "revoke all on t from anon; grant select on t to anon;",
        "anon",
        "insert",
        False,
        D,
    ),
    (
        "auth.role() = authenticated",
        "create policy p on t using (auth.role() = 'authenticated');",
        "authenticated",
        "select",
        True,
        A,
    ),
    (
        "auth.role() = authenticated, anon denied",
        "create policy p on t using (auth.role() = 'authenticated');",
        "anon",
        "select",
        True,
        D,
    ),
    (
        "auth.role() in list",
        "create policy p on t using ((select auth.role()) in ('anon','authenticated'));",
        "anon",
        "select",
        True,
        A,
    ),
    (
        "auth.uid() is not null",
        "create policy p on t using (auth.uid() is not null);",
        "authenticated",
        "select",
        True,
        A,
    ),
    (
        "auth.uid() is not null denies anon",
        "create policy p on t using (auth.uid() is not null);",
        "anon",
        "select",
        True,
        D,
    ),
    (
        "boolean column -> conditional",
        "create policy p on t using (is_public);",
        "anon",
        "select",
        True,
        C,
    ),
    (
        "is_public or owner",
        "create policy p on t using (is_public or (select auth.uid()) = user_id);",
        "authenticated",
        "select",
        True,
        C,
    ),
    (
        "exists subquery -> unknown",
        "create policy p on t using (exists (select 1 from t x where x.id = t.id));",
        "authenticated",
        "select",
        True,
        U,
    ),
    (
        "custom function -> unknown",
        "create policy p on t using (is_member(id));",
        "authenticated",
        "select",
        True,
        U,
    ),
    ("1 = 1 is true", "create policy p on t using (1 = 1);", "anon", "select", True, A),
    ("literal false", "create policy p on t using (false);", "anon", "select", True, D),
    ("not false", "create policy p on t using (not false);", "anon", "select", True, A),
    (
        "jwt claim -> conditional",
        "create policy p on t using ((auth.jwt() ->> 'role') = 'admin');",
        "authenticated",
        "select",
        True,
        C,
    ),
    (
        "true AND owner -> conditional",
        "create policy p on t using (true and auth.uid() = user_id);",
        "authenticated",
        "select",
        True,
        C,
    ),
    ("false OR true", "create policy p on t using (false or true);", "anon", "select", True, A),
    (
        "delete-only policy leaves select closed",
        "create policy p on t for delete using (true);",
        "authenticated",
        "select",
        True,
        D,
    ),
    (
        "unknown OR conditional stays unknown",
        "create policy p on t using (is_member(id) or is_public);",
        "authenticated",
        "select",
        True,
        U,
    ),
]


@pytest.mark.parametrize(
    ("desc", "sql", "role", "command", "rls", "expected"),
    CASES,
    ids=[c[0] for c in CASES],
)
def test_effective_access(
    desc: str, sql: str, role: str, command: str, rls: bool, expected: AccessKind
) -> None:
    assert acc(sql, role, command, rls=rls).kind is expected, desc


def test_case_count() -> None:
    assert len(CASES) >= 25


def test_owner_columns_reported() -> None:
    result = acc("create policy p on t using (auth.uid() = user_id);", "authenticated", "select")
    assert result.kind is C and result.owner_columns == ("user_id",)
    assert result.policies == ("p",)


def test_private_schema_has_no_platform_grants() -> None:
    table = "create table private.t (id int);"
    assert acc("", "anon", "select", rls=False, table=table).kind is D
    assert (
        acc("", "service_role", "select", rls=False, table=table).kind is D
    )  # no privilege at all
    opened = acc("grant select on private.t to public;", "anon", "select", rls=False, table=table)
    assert opened.kind is A


def test_force_rls_does_not_change_platform_roles() -> None:
    result = acc("alter table t force row level security;", "anon", "select")
    assert result.kind is D


def test_invalid_command() -> None:
    with pytest.raises(ValueError):
        acc("", "anon", "truncate")
