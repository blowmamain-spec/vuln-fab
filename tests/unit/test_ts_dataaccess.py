# ruff: noqa: E501
from vulnfab.core.models import DataAccess, SourceFile
from vulnfab.core.parsing import parse_file
from vulnfab.plugins.typescript.dataaccess import classify_key, extract
from vulnfab.plugins.typescript.resolve import resolve_module


def run(files: dict[str, str]) -> tuple[list[DataAccess], list]:  # type: ignore[type-arg]
    parsed = {}
    for path, code in files.items():
        lang = "tsx" if path.endswith("x") else "typescript"
        parsed[path] = parse_file(SourceFile(path, lang, code, "0" * 64))
    return extract(parsed)


def one(code: str, path: str = "a.ts") -> DataAccess:
    accesses, _ = run({path: code})
    assert len(accesses) == 1, accesses
    return accesses[0]


HEADER = 'import { createClient } from "@supabase/supabase-js";\n'
ANON = HEADER + "const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n"
SERVICE = HEADER + "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n"


def test_classify_key() -> None:
    assert classify_key("process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY") == "service_role"
    assert classify_key("Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')") == "service_role"
    assert classify_key("serviceRoleKey") == "service_role"
    assert classify_key("process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY") == "anon"
    assert classify_key("process.env.SUPABASE_PUBLISHABLE_KEY") == "anon"
    assert classify_key("someKey") == "unknown"


def test_basic_select_and_kinds() -> None:
    a = one(ANON + 'await supabase.from("todos").select("*");\n')
    assert (a.table, a.op, a.client_kind, a.line) == ("todos", "select", "anon", 3)
    s = one(SERVICE + 'await admin.from("orders").delete().eq("id", 1);\n')
    assert (s.table, s.op, s.client_kind) == ("orders", "delete", "service_role")


def test_operations() -> None:
    for method, op in [("insert", "insert"), ("update", "update"), ("upsert", "upsert"),
                       ("delete", "delete"), ("select", "select")]:  # fmt: skip
        assert one(ANON + f'supabase.from("t").{method}({{}});\n').op == op


def test_first_operation_wins_when_chained() -> None:
    assert one(ANON + 'supabase.from("t").insert({}).select();\n').op == "insert"


def test_filters_and_columns() -> None:
    a = one(
        ANON + 'supabase.from("t").select().eq("id", params.id).eq("user_id", user.id).single();\n'
    )
    assert a.filter_columns == ("id", "user_id")
    assert a.filters == (("id", "params.id"), ("user_id", "user.id"))
    m = one(ANON + 'supabase.from("t").update({ a: 1 }).match({ id: 5, owner_id: uid });\n')
    assert m.filters == (("id", "5"), ("owner_id", "uid"))
    f = one(ANON + 'supabase.from("t").select().filter("id", "eq", x).in("k", [1]);\n')
    assert f.filters == (("id", "x"), ("k", "[1]"))


def test_multiline_chain_span_and_line() -> None:
    a = one(ANON + 'const r = await supabase\n  .from("todos")\n  .select("*")\n  .eq("id", 1);\n')
    assert (a.line, a.end_line) == (3, 6)


def test_generic_type_arguments_and_await() -> None:
    a = one(ANON + 'const r = await supabase.from<Row>("todos").select("*");\n')
    assert a.table == "todos" and a.client_kind == "anon"


def test_rpc() -> None:
    a = one(ANON + 'await supabase.rpc("get_user_data", { uid });\n')
    assert (a.op, a.table) == ("rpc", "get_user_data")


def test_schema_chain() -> None:
    a = one(ANON + 'await supabase.schema("private").from("t").select();\n')
    assert (a.schema, a.table) == ("private", "t")


def test_inline_create_client() -> None:
    a = one(HEADER + 'await createClient(u, process.env.SERVICE_ROLE_KEY).from("t").select();\n')
    assert a.client_kind == "service_role"


def test_const_table_name_and_template_literal() -> None:
    a = one(ANON + 'const T = "notes";\nsupabase.from(T).select();\n')
    assert a.table == "notes"
    b = one(ANON + "supabase.from(`notes`).select();\n")
    assert b.table == "notes"


def test_dynamic_table_is_unresolved_not_a_fact() -> None:
    accesses, unresolved = run({"a.ts": ANON + "supabase.from(name).select();\n"})
    assert accesses == [] and [u.kind for u in unresolved] == ["dynamic_table"]
    accesses, unresolved = run({"a.ts": ANON + "supabase.from(`t_${x}`).select();\n"})
    assert accesses == [] and len(unresolved) == 1


def test_non_supabase_from_calls_are_ignored() -> None:
    code = "const a = Array.from(xs);\nconst b = Buffer.from('x');\nconst c = rx.from(y);\nconst d = obs.from(z).pipe();\n"  # noqa: E501
    accesses, _ = run({"a.ts": code})
    assert accesses == []


def test_storage_from_is_not_a_table() -> None:
    accesses, _ = run({"a.ts": ANON + 'supabase.storage.from("avatars").upload("a", f);\n'})
    assert accesses == []


def test_unknown_client_parameter() -> None:
    a = one("export async function f(db: SupabaseClient) { return db.from('t').select(); }\n")
    assert a.client_kind == "unknown"


def test_client_imported_across_files() -> None:
    files = {
        "lib/supabase.ts": HEADER
        + "export const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n"
        + "export const admin = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);\n",
        "pages/a.tsx": 'import { supabase } from "../lib/supabase";\nsupabase.from("a").select();\n',
        "pages/b.tsx": 'import { admin as db } from "../lib/supabase";\ndb.from("b").select();\n',
    }
    accesses, _ = run(files)
    assert {(a.table, a.client_kind) for a in accesses} == {("a", "anon"), ("b", "service_role")}


def test_default_export_and_reexport() -> None:
    files = {
        "lib/client.ts": HEADER + "export default createClient(url, process.env.ANON_KEY!);\n",
        "lib/index.ts": 'export { default as supabase } from "./client";\n',
        "a.ts": 'import client from "./lib/client";\nclient.from("a").select();\n',
    }
    accesses, _ = run(files)
    assert [(a.table, a.client_kind) for a in accesses] == [("a", "anon")]


def test_alias_and_index_resolution() -> None:
    files = {
        "src/lib/supabase/index.ts": HEADER
        + "export const supabase = createClient(u, ANON_KEY);\n",
        "src/app/page.tsx": 'import { supabase } from "@/lib/supabase";\nsupabase.from("t").select();\n',
    }
    accesses, _ = run(files)
    assert [(a.table, a.client_kind) for a in accesses] == [("t", "anon")]


def test_factory_functions() -> None:
    files = {
        "lib/admin.ts": HEADER
        + "export function getAdmin() {\n  return createClient(u, process.env.SERVICE_ROLE_KEY!);\n}\n",
        "a.ts": 'import { getAdmin } from "./lib/admin";\nconst db = getAdmin();\ndb.from("t").delete();\n',
        "b.ts": HEADER
        + "const make = () => createClient(u, ANON_KEY);\nconst c = make();\nc.from('u').select();\n",
    }
    accesses, _ = run(files)
    assert {(a.table, a.client_kind) for a in accesses} == {("t", "service_role"), ("u", "anon")}


def test_auth_helpers_are_session_clients() -> None:
    code = 'import { createServerComponentClient } from "@supabase/auth-helpers-nextjs";\n'
    a = one(code + 'const s = createServerComponentClient({ cookies });\ns.from("t").select();\n')
    assert a.client_kind == "user"
    b = one(
        code
        + 'const s = createServerClient(url, process.env.ANON_KEY!, { cookies });\ns.from("t").select();\n'
    )  # noqa: E501
    assert b.client_kind == "user"


def test_resolve_module() -> None:
    known = {"a/b.ts", "a/c/index.tsx", "src/lib/x.ts", "lib/y.ts"}
    assert resolve_module("a/z.ts", "./b", known) == "a/b.ts"
    assert resolve_module("a/z.ts", "./c", known) == "a/c/index.tsx"
    assert resolve_module("a/z.ts", "./b.js", known) == "a/b.ts"
    assert resolve_module("app/page.tsx", "@/lib/x", known) == "src/lib/x.ts"
    assert resolve_module("app/page.tsx", "@/lib/y", known) == "lib/y.ts"
    assert resolve_module("a/z.ts", "react", known) is None
    assert resolve_module("a/z.ts", "./missing", known) is None
