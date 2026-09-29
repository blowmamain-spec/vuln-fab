# ruff: noqa: E501
"""Regression tests distilled from scanning the official supabase/supabase examples.

Each case was a false positive (or an unhelpfully loud true positive) on real projects.
"""

import base64
import json
from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence, SourceFile
from vulnfab.scanners.secrets import scan_file


def _scan(tmp_path: Path, files: dict[str, str]) -> dict[str, list]:  # type: ignore[type-arg]
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    result = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW))
    out: dict[str, list] = {}  # type: ignore[type-arg]
    for f in result.findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


def _migration(sql: str) -> dict[str, str]:
    return {"supabase/migrations/20240101000000_x.sql": sql}


def test_policy_using_custom_helper_is_not_a_confident_anon_write(tmp_path: Path) -> None:
    sql = (
        "create table public.channels (id int);\n"
        "alter table public.channels enable row level security;\n"
        "create policy p on public.channels for delete using (authorize('channels.delete'));\n"
    )
    hits = _scan(tmp_path, _migration(sql)).get("sb-policy-anon-write", [])
    assert [h.confidence for h in hits] == [Confidence.LOW]


def test_anon_write_with_row_condition_only_is_confident(tmp_path: Path) -> None:
    sql = (
        "create table public.t (id int, created_at timestamptz);\n"
        "alter table public.t enable row level security;\n"
        "create policy p on public.t for update to anon using (created_at > now());\n"
    )
    hits = _scan(tmp_path, _migration(sql))["sb-policy-anon-write"]
    assert [h.confidence for h in hits] == [Confidence.HIGH]


def test_public_profiles_select_true_is_low_but_owned_data_is_high(tmp_path: Path) -> None:
    sql = (
        "create table public.profiles (id uuid, username text);\n"
        "alter table public.profiles enable row level security;\n"
        "create policy pub on public.profiles for select using (true);\n"
        "create table public.invoices (id int, user_id uuid);\n"
        "alter table public.invoices enable row level security;\n"
        "create policy inv on public.invoices for select using (true);\n"
        "create policy w on public.profiles for insert with check (true);\n"
    )
    hits = _scan(tmp_path, _migration(sql))["sb-policy-true"]
    by_line = {h.line: h.confidence for h in hits}
    assert by_line[3] is Confidence.LOW  # public profiles
    assert by_line[6] is Confidence.HIGH  # rows belong to users
    assert by_line[7] is Confidence.HIGH  # writes are never "public data"


def test_grant_all_to_anon_on_rls_table_is_low_without_rls_is_high(tmp_path: Path) -> None:
    sql = (
        "create table public.a (id int);\nalter table public.a enable row level security;\n"
        "create table public.b (id int);\n"
        "grant all on table public.a to anon;\n"
        "grant all on table public.b to anon;\n"
    )
    hits = _scan(tmp_path, _migration(sql))["sb-grant-broad"]
    assert {h.line: h.confidence for h in hits} == {4: Confidence.LOW, 5: Confidence.HIGH}


def test_default_privileges_for_postgres_role_are_platform_boilerplate(tmp_path: Path) -> None:
    sql = (
        'alter default privileges for role "postgres" in schema "public" grant all on tables to "anon";\n'
        "alter default privileges in schema public grant all on tables to anon;\n"
    )
    hits = _scan(tmp_path, _migration(sql))["sb-default-priv"]
    assert {h.line: h.confidence for h in hits} == {1: Confidence.LOW, 2: Confidence.HIGH}


def test_config_signup_is_a_low_confidence_dev_default(tmp_path: Path) -> None:
    toml = "[auth.email]\nenable_signup = true\nenable_confirmations = false\n"
    hits = _scan(tmp_path, {"supabase/config.toml": toml})["sb-config-signup"]
    assert [h.confidence for h in hits] == [Confidence.LOW]


def test_edge_no_jwt_confidence_depends_on_what_the_function_does(tmp_path: Path) -> None:
    files = {
        "supabase/config.toml": (
            "[functions.hello]\nverify_jwt = false\n\n[functions.admin]\nverify_jwt = false\n"
        ),
        "supabase/functions/hello/index.ts": "Deno.serve(() => new Response('hi'));\n",
        "supabase/functions/admin/index.ts": (
            "const c = createClient(u, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\n"
        ),
    }
    hits = _scan(tmp_path, files)["sb-edge-no-jwt"]
    conf = {"hello" if "hello" in h.message else "admin": h.confidence for h in hits}
    assert conf == {"hello": Confidence.LOW, "admin": Confidence.MEDIUM}


def _fn(param: str, body_args: str) -> str:
    return (
        f"create function public.f({param}) returns void language plpgsql set search_path = '' as $$\n"
        "begin\n"
        f"  execute format('select * from %I where a = %s', 'public.t', {body_args});\n"
        "end;\n$$;\n"
    )


def test_dynamic_sql_ignores_non_text_parameters(tmp_path: Path) -> None:
    safe = _scan(tmp_path / "a", _migration(_fn("d date", "d")))
    assert "sb-dynamic-sql" not in safe
    risky = _scan(tmp_path / "b", _migration(_fn("t text", "t")))
    assert "sb-dynamic-sql" in risky


def _jwt(payload: dict) -> str:  # type: ignore[type-arg]
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    return f"{head}.{b64(json.dumps(payload).encode())}.{b64(b'signaturesignature')}"


def test_supabase_demo_key_is_public_but_a_real_service_role_jwt_is_a_secret() -> None:
    demo = _jwt({"iss": "supabase-demo", "role": "service_role"})
    real = _jwt({"iss": "supabase", "role": "service_role", "ref": "abcdefghij"})
    anon = _jwt({"iss": "supabase", "role": "anon"})

    def hits(token: str) -> int:
        sf = SourceFile("a.ts", "typescript", f"const k = '{token}';\n", "0" * 64)
        return len(list(scan_file(sf)))

    assert (hits(demo), hits(real), hits(anon)) == (0, 1, 0)


def test_encrypted_dotenv_values_are_not_secrets() -> None:
    text = "GITHUB_SECRET=encrypted:BJ9MabcdefghijklmnopqrstuvwxYZ0123456789ABCDEFGHIJKLMNOP=\n"
    assert list(scan_file(SourceFile(".env", "env", text, "0" * 64))) == []


def test_provider_patterns_built_at_runtime() -> None:
    # assembled at runtime so no secret-looking literal exists in the repository
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    text = f"a = '{aws}'\nb = '{gh}'\nc = 'nothing here'\n"
    found = [what for _, what, _, _ in scan_file(SourceFile("a.py", "python", text, "0" * 64))]
    assert found == ["AWS access key id", "GitHub token"]
