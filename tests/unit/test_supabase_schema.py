from pathlib import Path

from vulnfab.plugins.supabase.schema import SchemaBuilder

LAB = Path(__file__).resolve().parents[2] / "benchmarks" / "labs" / "supabase-vuln" / "supabase"


def build(*sqls: str):  # type: ignore[no-untyped-def]
    b = SchemaBuilder()
    for i, sql in enumerate(sqls, start=1):
        b.apply_file(f"m{i}.sql", sql)
    return b.model


def test_create_table_defaults_and_columns() -> None:
    m = build("create table t (id int primary key, user_id uuid not null, note text);")
    t = m.tables["public.t"]
    assert (t.schema, t.name, t.rls_enabled, t.external) == ("public", "t", False, False)
    assert [(c.name, c.nullable) for c in t.columns] == [
        ("id", False),  # primary key
        ("user_id", False),
        ("note", True),
    ]
    assert (t.line, t.rls_line, t.rls_file) == (1, 1, "m1.sql")


def test_schema_qualified_and_if_not_exists() -> None:
    m = build("create table private.a (id int);", "create table if not exists private.a (x int);")
    assert [c.name for c in m.tables["private.a"].columns] == ["id"]


def test_temp_tables_are_ignored() -> None:
    assert build("create temp table t (id int);").tables == {}


def test_rls_enable_disable_force_and_location() -> None:
    m = build(
        "create table t (id int);",
        "alter table t enable row level security;\nalter table t force row level security;",
        "alter table t disable row level security;",
    )
    t = m.tables["public.t"]
    assert t.rls_enabled is False and t.rls_forced is True
    assert (t.rls_file, t.rls_line) == ("m3.sql", 1)  # last statement that set the state
    m = build("create table t (id int);", "alter table t enable row level security;",
              "alter table t no force row level security;")  # fmt: skip
    assert m.tables["public.t"].rls_enabled and not m.tables["public.t"].rls_forced


def test_combined_alter_commands_and_columns() -> None:
    m = build(
        "create table t (a int);",
        "alter table t enable row level security, add column b text;",
        "alter table t drop column a;",
    )
    t = m.tables["public.t"]
    assert t.rls_enabled and [c.name for c in t.columns] == ["b"]


def test_drop_then_recreate_resets_state() -> None:
    m = build(
        "create table t (id int); alter table t enable row level security;",
        "create policy p on t using (true);",
        "drop table t;",
        "create table t (id int);",
    )
    t = m.tables["public.t"]
    assert not t.rls_enabled and t.policies == []


def test_drop_multiple_and_if_exists() -> None:
    m = build("create table a (i int); create table b (i int);", "drop table if exists a, b, c;")
    assert m.tables == {}


def test_rename_table_column_policy_and_set_schema() -> None:
    m = build(
        "create table t (a int); alter table t enable row level security;",
        "create policy p on t using (true);",
        "alter table t rename column a to b;",
        "alter policy p on t rename to q;",
        "alter table t rename to u;",
        "alter table u set schema private;",
    )
    assert list(m.tables) == ["private.u"]
    t = m.tables["private.u"]
    assert [c.name for c in t.columns] == ["b"]
    assert [(p.name, p.table) for p in t.policies] == [("q", "u")]


def test_policies_create_alter_drop() -> None:
    m = build(
        "create table t (id int);",
        "create policy a on t as restrictive for update to anon, authenticated "
        "using (x = 1) with check (y = 2);",
        "create policy b on t using (true);",
        "alter policy b on t to authenticated using (false);",
        "drop policy a on t;",
    )
    (b,) = m.tables["public.t"].policies
    assert (b.name, b.roles, b.using_expr, b.permissive, b.command) == (
        "b", ("authenticated",), "FALSE", True, "all"
    )  # fmt: skip
    m = build("create table t (id int);", "create policy a on t as restrictive for update "
              "to anon using (x = 1) with check (y = 2);")  # fmt: skip
    a = m.tables["public.t"].policies[0]
    assert (a.permissive, a.command, a.roles, a.using_expr, a.check_expr) == (
        False, "update", ("anon",), "x = 1", "y = 2"
    )  # fmt: skip
    assert m.tables["public.t"].policies[0].roles == ("anon",)


def test_policy_default_role_is_public() -> None:
    m = build("create table t (id int);", "create policy a on t for select using (true);")
    assert m.tables["public.t"].policies[0].roles == ("public",)


def test_policy_on_unknown_table_creates_external_placeholder() -> None:
    m = build(
        "create policy a on storage.objects for insert to public with check (bucket_id = 'x');"
    )
    t = m.tables["storage.objects"]
    assert t.external and t.rls_enabled and len(t.policies) == 1


def test_baseline_default_privileges_grant_platform_roles() -> None:
    m = build("create table t (id int);", "create table private.p (id int);")
    roles = {g.role for g in m.tables["public.t"].grants}
    assert roles == {"anon", "authenticated", "service_role"}
    assert all(g.inherited_default for g in m.tables["public.t"].grants)
    assert m.tables["private.p"].grants == []


def test_grant_revoke_and_all_in_schema() -> None:
    m = build(
        "create table t (id int);",
        "revoke all on t from anon;",
        "grant select on t to anon;",
        "revoke insert, update on public.t from authenticated;",
    )
    grants = {g.role: g.privileges for g in m.tables["public.t"].grants}
    assert grants["anon"] == {"select"}
    assert "insert" not in grants["authenticated"] and "select" in grants["authenticated"]
    m = build(
        "create table private.p (id int);", "grant all on all tables in schema private to anon;"
    )
    assert {g.role for g in m.tables["private.p"].grants} == {"anon"}


def test_grant_to_public_and_with_grant_option() -> None:
    m = build(
        "create table private.t (i int);", "grant select on private.t to public with grant option;"
    )
    (g,) = m.tables["private.t"].grants
    assert (g.role, g.privileges, g.with_grant) == ("public", frozenset({"select"}), True)


def test_alter_default_privileges_apply_to_later_tables_only() -> None:
    m = build(
        "create table private.before (i int);",
        "alter default privileges in schema private grant select on tables to anon;",
        "create table private.after (i int);",
    )
    assert m.tables["private.before"].grants == []
    assert [(g.role, g.privileges) for g in m.tables["private.after"].grants] == [
        ("anon", {"select"})
    ]
    dp = [d for d in m.default_privileges if not d.baseline]
    assert len(dp) == 1 and dp[0].schema == "private" and dp[0].grantees == ("anon",)
    m = build(
        "alter default privileges for role postgres in schema public revoke all on tables from anon;",  # noqa: E501
        "create table t (i int);",
    )
    assert "anon" not in {g.role for g in m.tables["public.t"].grants}


def test_functions_definer_search_path_and_alter() -> None:
    m = build(
        "create function f(a text) returns int language sql security definer as $$ select 1 $$;",
        "create function g() returns int language plpgsql security definer set search_path = '' "
        "as $$ begin return 1; end $$;",
        "create function h() returns int language sql as $$ select 1 $$;",
        "alter function h() security definer;",
        "alter function h() set search_path = public, extensions;",
    )
    f, g, h = (m.functions[k] for k in ("public.f(1)", "public.g(0)", "public.h(0)"))
    assert (f.security_definer, f.search_path, f.language, f.param_names) == (
        True,
        None,
        "sql",
        ("a",),
    )
    assert (g.security_definer, g.search_path, g.language) == (True, "", "plpgsql")
    assert (h.security_definer, h.search_path) == (True, "public, extensions")
    assert "select 1" in f.body and f.sql.lstrip().lower().startswith("create function")


def test_create_or_replace_function_replaces() -> None:
    m = build(
        "create function f() returns int language sql security definer as $$ select 1 $$;",
        "create or replace function f() returns int language sql as $$ select 2 $$;",
    )
    assert m.functions["public.f(0)"].security_definer is False


def test_views_security_invoker() -> None:
    m = build(
        "create view v1 as select 1;",
        "create view v2 with (security_invoker = true) as select 1;",
        "create view v3 with (security_invoker = false) as select 1;",
        "drop view v3;",
    )
    assert (m.views["public.v1"].security_invoker, m.views["public.v2"].security_invoker) == (
        False,
        True,
    )
    assert "public.v3" not in m.views


def test_storage_buckets() -> None:
    m = build(
        "insert into storage.buckets (id, name, public) values ('a','a',true), ('b','b',false);",
        "insert into storage.buckets (id, public) values ('c', true);",
        "insert into storage.buckets (id, name) select 'd', 'd';",
    )
    assert {k: v.public for k, v in m.buckets.items()} == {"a": True, "b": False, "c": True}
    assert [u.kind for u in m.unresolved] == ["dynamic_bucket"]


def test_static_do_blocks_are_applied_and_parse_errors_are_unresolved() -> None:
    m = build(
        "do $$ begin create table x(i int); end $$;\ncreate table ok (i int);\ncreate tabl bad;"
    )
    assert list(m.tables) == ["public.x", "public.ok"]  # static DDL inside DO is analysed
    assert [(u.kind, u.line) for u in m.unresolved] == [("sql_parse_error", 3)]


def test_drop_schema_cascades_in_model() -> None:
    m = build("create table private.a (i int); create view private.v as select 1;",
              "drop schema private cascade;")  # fmt: skip
    assert m.tables == {} and m.views == {}


def test_assumption_recorded() -> None:
    assert any("default privileges" in a for a in build("select 1;").assumptions)


# --- the lab -----------------------------------------------------------------------------------


def _lab():  # type: ignore[no-untyped-def]
    b = SchemaBuilder()
    for path in sorted((LAB / "migrations").glob("*.sql")):
        b.apply_file(f"supabase/migrations/{path.name}", path.read_text())
    return b.model


def test_lab_final_state() -> None:
    m = _lab()
    t = m.tables
    assert not t["public.audit_log"].rls_enabled
    assert t["public.profiles"].rls_enabled and t["public.late_rls"].rls_enabled
    reports = t["public.reports"]
    assert not reports.rls_enabled and reports.rls_file.endswith(
        "20240103000000_storage_and_fixes.sql"
    )
    assert reports.rls_line == 26  # the DISABLE statement, not the CREATE
    assert not t["private.internal_notes"].rls_enabled
    assert {p.name for p in t["public.invoices"].policies} == {
        "invoices_select_all",
        "invoices_insert_own",
    }
    assert m.functions["public.get_user_data(1)"].search_path is None
    assert m.functions["public.get_my_profile(0)"].search_path == ""
    assert m.views["public.user_stats"].security_invoker is False
    assert m.views["public.my_todo_stats"].security_invoker is True
    assert {k: b.public for k, b in m.buckets.items()} == {
        "invoices": True,
        "avatars": True,
        "contracts": False,
    }
    assert len(t["storage.objects"].policies) == 2
    assert m.unresolved == []
    anon_audit = next(g for g in t["public.audit_log"].grants if g.role == "anon")
    assert "delete" in anon_audit.privileges
