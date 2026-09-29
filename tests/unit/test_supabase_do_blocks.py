from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence
from vulnfab.plugins.supabase.schema import SchemaBuilder


def build(*sqls: str):  # type: ignore[no-untyped-def]
    b = SchemaBuilder()
    for i, sql in enumerate(sqls, start=1):
        b.apply_file(f"m{i}.sql", sql)
    return b.model


def test_static_ddl_inside_do_block_is_applied() -> None:
    m = build(
        "create table public.t (id int, user_id uuid);\n"
        "do $$ begin\n  alter table public.t enable row level security;\nend $$;\n"
    )
    t = m.tables["public.t"]
    assert t.rls_enabled and (t.rls_file, t.rls_line) == ("m1.sql", 2)
    assert m.unresolved == []


def test_idempotent_policy_creation_is_understood() -> None:
    m = build(
        "create table public.t (id int, user_id uuid);\n"
        "alter table public.t enable row level security;\n"
        "do $$\nbegin\n  if not exists (select 1 from pg_policies where policyname = 'own') then\n"
        "    create policy own on public.t for all to authenticated\n"
        "      using ((select auth.uid()) = user_id);\n  end if;\nend\n$$;\n"
    )
    (policy,) = m.tables["public.t"].policies
    assert (policy.name, policy.roles) == ("own", ("authenticated",))
    assert m.unresolved == []


def test_dynamic_execute_is_unresolved_and_flags_rls_uncertainty() -> None:
    m = build(
        "create table public.t (id int);\n"
        "do $$ declare r record; begin\n"
        "  for r in select tablename from pg_tables where schemaname = 'public' loop\n"
        "    execute format('alter table public.%I enable row level security', r.tablename);\n"
        "  end loop;\nend $$;\n"
    )
    assert [u.kind for u in m.unresolved] == ["do_block"]
    assert m.dynamic_rls_blocks == [("m1.sql", 2)]
    assert not m.tables["public.t"].rls_enabled  # not guessed


def test_rls_missing_is_low_confidence_when_dynamic_rls_exists(tmp_path) -> None:  # type: ignore[no-untyped-def]
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "20240101000000_a.sql").write_text(
        "create table public.t (id int);\n"
        "do $$ begin execute 'alter table public.t enable row level security'; end $$;\n"
    )
    result = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW))
    (hit,) = [f for f in result.findings if f.rule_id == "sb-rls-missing"]
    assert hit.confidence is Confidence.LOW and "could not be verified" in hit.message
    visible = scan(tmp_path)
    assert [f for f in visible.findings if f.rule_id == "sb-rls-missing"] == []


def test_non_plpgsql_or_broken_do_blocks_are_unresolved() -> None:
    m = build("do language plpython3u $$ plpy.execute('select 1') $$;\n")
    assert [u.kind for u in m.unresolved] == ["do_block"]
    m = build("do $$ begin this is not valid plpgsql $$;\n")
    assert [u.kind for u in m.unresolved] == ["do_block"]
