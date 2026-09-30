"""Check functions for Supabase schema rules (referenced from rules/supabase/*.yml).

Each check receives a :class:`CheckContext` and yields :class:`SchemaHit`. Locations point at
the statement that *determines* the problem (see docs/spec.md, section 8).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from pglast import ast as A
from pglast.visitors import Visitor

from vulnfab.core.models import Confidence, Policy, Table, TraceStep
from vulnfab.core.schemarules import CheckContext, SchemaHit
from vulnfab.core.sqlparser import PglastParser
from vulnfab.plugins.supabase import exposed_schemas
from vulnfab.plugins.supabase.access import (
    AccessKind,
    eval_expr,
    mentions_function,
    policy_expression,
)
from vulnfab.plugins.supabase.schema import ALL_TABLE_PRIVILEGES

WRITE_PRIVILEGES = frozenset({"insert", "update", "delete", "truncate"})
CLIENT_ROLES = frozenset({"anon", "authenticated", "public"})
WRITE_COMMANDS = {"insert": ("insert",), "update": ("update",), "delete": ("delete",),
                  "all": ("insert", "update", "delete")}  # fmt: skip
SENSITIVE_BUCKET = re.compile(
    r"invoice|contract|document|private|secret|receipt|report|billing|kyc|passport|medical|"
    r"payroll|statement|confidential|backup|export|credential|tax|hr",
    re.I,
)
USER_METADATA = re.compile(r"user_metadata|raw_user_meta_data", re.I)
STORAGE_OWNERSHIP = re.compile(r"auth\.|owner|foldername|\(\s*select", re.I)


def _policies(ctx: CheckContext) -> Iterator[tuple[Table, Policy]]:
    for table in ctx.model.tables.values():
        for policy in table.policies:
            yield table, policy


OWNER_COLUMNS = frozenset({"user_id", "owner_id", "created_by", "author_id", "profile_id"})


def _has_owner_column(table: Table) -> bool:
    return any(c.name in OWNER_COLUMNS for c in table.columns)


def _client_facing(policy: Policy) -> bool:
    return bool(CLIENT_ROLES & set(policy.roles))


def _trace_policy(table: Table, policy: Policy, note: str) -> tuple[TraceStep, ...]:
    return (TraceStep(policy.file, policy.line, "policy", f"{table.qualified_name}: {note}"),)


def _is_literal_true(node: Any) -> bool:
    if node is None:
        return False
    result = eval_expr(node, "authenticated")
    return result.kind is AccessKind.ALLOW and result.reason in (
        "literal true",
        "constant comparison",
    )


def _functions_in(node: Any) -> set[tuple[str, ...]]:
    if node is None:
        return set()

    class _V(Visitor):
        def __init__(self) -> None:
            super().__init__()
            self.found: set[tuple[str, ...]] = set()

        def visit_FuncCall(self, ancestors: Any, n: Any) -> None:
            self.found.add(tuple(str(x.sval).lower() for x in (n.funcname or ())))

    v = _V()
    v(node)
    return v.found


# --- tables -------------------------------------------------------------------------------------


def rls_missing(ctx: CheckContext) -> Iterator[SchemaHit]:
    exposed = exposed_schemas(ctx.model)
    for t in ctx.model.tables.values():
        if t.schema not in exposed or t.rls_enabled:
            continue
        if t.external and not t.rls_line:
            continue  # created outside the migrations and never toggled: unknown, not a finding
        dynamic = ctx.model.dynamic_rls_blocks
        note = (
            f" A DO block with dynamic SQL that mentions RLS/policies "
            f"({dynamic[0][0]}:{dynamic[0][1]}) may enable it; this could not be verified."
            if dynamic
            else ""
        )
        yield SchemaHit(
            t.rls_file,
            t.rls_line,
            t.rls_end_line,
            f"Table {t.qualified_name} is exposed through the API but Row Level Security is off."
            + note,
            trace=(TraceStep(t.rls_file, t.rls_line, "schema", f"RLS off for {t.qualified_name}"),),
            symbol=t.qualified_name,
            confidence=Confidence.LOW if dynamic else None,
        )


# --- policies -----------------------------------------------------------------------------------


def policy_true(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table, p in _policies(ctx):
        if not p.permissive or not _client_facing(p):
            continue
        nodes = {
            "select": [p.using_node], "delete": [p.using_node], "insert": [p.check_node],
            "update": [p.using_node, p.check_node], "all": [p.using_node, p.check_node],
        }[p.command]  # fmt: skip
        if any(_is_literal_true(n) for n in nodes):
            # Public read of rows nobody owns ("public profiles") is usually intentional.
            public_read = p.command == "select" and not _has_owner_column(table)
            yield SchemaHit(
                p.file,
                p.line,
                p.end_line,
                f"Policy {p.name!r} on {table.qualified_name} allows {p.command.upper()} for "
                f"{', '.join(p.roles)} with no row condition (expression is TRUE).",
                trace=_trace_policy(table, p, f"policy {p.name} is TRUE"),
                symbol=f"{table.qualified_name}:{p.name}",
                confidence=Confidence.LOW if public_read else None,
            )


def policy_anon_write(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table, p in _policies(ctx):
        if table.schema == "storage" or not p.permissive or not ({"anon", "public"} & set(p.roles)):
            continue
        results = {
            c: policy_expression(p, c, "anon").kind for c in WRITE_COMMANDS.get(p.command, ())
        }
        open_commands = [c for c, kind in results.items() if kind is not AccessKind.DENY]
        certain = any(
            kind in (AccessKind.ALLOW, AccessKind.CONDITIONAL) for kind in results.values()
        )
        if open_commands:
            yield SchemaHit(
                p.file,
                p.line,
                p.end_line,
                f"Policy {p.name!r} on {table.qualified_name} lets unauthenticated (anon) users "
                f"{'/'.join(c.upper() for c in open_commands)} rows.",
                trace=_trace_policy(table, p, f"anon may {', '.join(open_commands)}"),
                symbol=f"{table.qualified_name}:{p.name}",
                # a custom helper (authorize(), is_member()) usually rejects anon: cannot tell
                confidence=None if certain else Confidence.LOW,
            )


def policy_user_metadata(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table, p in _policies(ctx):
        text = f"{p.using_expr or ''} {p.check_expr or ''}"
        if USER_METADATA.search(text):
            yield SchemaHit(
                p.file,
                p.line,
                p.end_line,
                f"Policy {p.name!r} on {table.qualified_name} trusts user_metadata, which end "
                "users can edit themselves. Use app_metadata or a roles table.",
                trace=_trace_policy(table, p, "authorization depends on user_metadata"),
                symbol=f"{table.qualified_name}:{p.name}",
            )


def policy_no_uid(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table, p in _policies(ctx):
        if "user_id" not in {c.name for c in table.columns}:
            continue
        if not p.permissive or not _client_facing(p):
            continue
        nodes = [n for n in (p.using_node, p.check_node) if n is not None]
        if not nodes or any(_is_literal_true(n) for n in nodes):
            continue  # TRUE policies are reported by policy_true
        if any(eval_expr(n, "authenticated").kind is AccessKind.DENY for n in nodes):
            continue
        if any(_functions_in(n) for n in nodes) or mentions_function(
            p.using_node, ("auth", "uid"), ("auth", "jwt")
        ):
            continue  # calls a function (auth.uid, custom helpers): cannot conclude
        yield SchemaHit(
            p.file,
            p.line,
            p.end_line,
            f"Policy {p.name!r} on {table.qualified_name} does not compare auth.uid() with the "
            "owner column although the table has user_id: any matching row is visible to every "
            "user the policy applies to.",
            trace=_trace_policy(table, p, "no auth.uid() ownership check"),
            symbol=f"{table.qualified_name}:{p.name}",
        )


# --- functions and views ------------------------------------------------------------------------


def definer_no_path(ctx: CheckContext) -> Iterator[SchemaHit]:
    for fn in ctx.model.functions.values():
        if fn.security_definer and fn.search_path is None:
            yield SchemaHit(
                fn.file,
                fn.line,
                fn.end_line,
                f"Function {fn.schema}.{fn.name} is SECURITY DEFINER without SET search_path: "
                "a caller can shadow objects it references.",
                symbol=f"{fn.schema}.{fn.name}",
            )


_AUTH_REF = re.compile(
    r"auth\s*\.\s*(?:uid|jwt|role|email)\s*\(|request\.jwt|current_setting\s*\(\s*'(?:request|role)|"
    r"session_user|current_user|get_my_|is_admin|has_role|is_staff",
    re.I,
)
_WRITES = re.compile(r"\b(?:update|delete\s+from|insert\s+into|truncate)\b", re.I)
_IDENTITY_PARAM = re.compile(
    r"(?:^|_)(?:user|akun|account|owner|member|profile|actor|caller|staff|admin)(?:_id|_uuid)?$",
    re.I,
)
_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)


def definer_no_auth(ctx: CheckContext) -> Iterator[SchemaHit]:
    """SECURITY DEFINER RPC that writes (or takes the caller's identity as an argument) but never
    consults auth.uid()/auth.jwt(): the caller decides who they are."""
    exposed = exposed_schemas(ctx.model)
    for fn in ctx.model.functions.values():
        if not fn.security_definer or fn.schema not in exposed:
            continue
        if re.search(r"returns\s+trigger", fn.sql or "", re.I):
            continue
        body = _COMMENT.sub(" ", fn.body or "")
        if not body.strip() or _AUTH_REF.search(body):
            continue
        writes = bool(_WRITES.search(body))
        identity = [n for n in fn.param_names if _IDENTITY_PARAM.search(n.lstrip("p_"))]
        if not (writes or identity):
            continue
        detail = (
            f"takes the caller's identity as an argument ({', '.join(identity)}) and "
            if identity
            else ""
        )
        yield SchemaHit(
            fn.file,
            fn.line,
            fn.end_line,
            f"Function {fn.schema}.{fn.name} is SECURITY DEFINER, {detail}"
            f"{'modifies data ' if writes else 'reads data '}without checking auth.uid(): any "
            "client that can call the RPC can act as any user it names. Ignore this if the RPC is "
            "a deliberate public entry point with its own validation and rate limit.",
            symbol=f"{fn.schema}.{fn.name}",
        )


def view_no_invoker(ctx: CheckContext) -> Iterator[SchemaHit]:
    exposed = exposed_schemas(ctx.model)
    for view in ctx.model.views.values():
        if view.schema in exposed and not view.security_invoker:
            yield SchemaHit(
                view.file,
                view.line,
                view.end_line,
                f"View {view.schema}.{view.name} runs with its owner's rights and bypasses RLS "
                "of the underlying tables. Add WITH (security_invoker = true).",
                symbol=f"{view.schema}.{view.name}",
            )


_SQL_STRING = re.compile(r"'(?:[^']|'')*'")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_QUOTE_CALL = re.compile(r"quote_(?:literal|ident|nullable)\s*\((?:[^()]|\([^()]*\))*\)", re.I)
_FORMAT_S = re.compile(r"%(?:\d+\$)?[-]?\d*s")


def unsafe_dynamic_query(text: str) -> bool:
    """Is the EXECUTE query expression built by unsafe concatenation / %s formatting?"""
    skeleton = _SQL_STRING.sub("''", text)
    lowered = skeleton.lower()
    if "format(" in lowered:
        if _FORMAT_S.search(text.replace("%%", "")):
            return True
        outside = re.sub(r"format\s*\(.*\)", "", skeleton, flags=re.I | re.S)
        return "||" in outside and bool(
            _IDENT.search(_QUOTE_CALL.sub("", outside.replace("||", " ")))
        )
    if "||" in skeleton:
        rest = _QUOTE_CALL.sub("", skeleton.replace("||", " ").replace("''", " "))
        return bool(_IDENT.search(rest))
    return False


def _dynamic_queries(node: Any) -> Iterator[tuple[str, int]]:
    """(query expression text, plpgsql line) of every dynamic EXECUTE in a parsed function."""

    def expr_text(holder: Any) -> str:
        return str(((holder or {}).get("PLpgSQL_expr") or {}).get("query", ""))

    if isinstance(node, dict):
        for key, value in node.items():
            if key == "PLpgSQL_stmt_dynexecute":
                yield expr_text(value.get("query")), int(value.get("lineno", 1))
            elif key == "PLpgSQL_stmt_return_query" and value.get("dynquery"):
                yield expr_text(value.get("dynquery")), int(value.get("lineno", 1))
            elif key == "PLpgSQL_stmt_dynfors":
                yield expr_text(value.get("query")), int(value.get("lineno", 1))
            yield from _dynamic_queries(value)
    elif isinstance(node, list):
        for item in node:
            yield from _dynamic_queries(item)


_NON_TEXT_TYPES = re.compile(
    r"^(?:date|time|timestamp\w*|interval|int\w*|bigint|smallint|serial\w*|numeric|decimal|real|"
    r"double precision|boolean|bool|uuid|oid|regclass)\b"
)


def _typed_arguments_only(fn: Any) -> bool:
    """True when the function has parameters and none of them can carry injected SQL."""
    if not fn.param_types:
        return False
    return all(_NON_TEXT_TYPES.match(t) for t in fn.param_types.values())


def dynamic_sql(ctx: CheckContext) -> Iterator[SchemaHit]:
    parser = PglastParser()
    for fn in ctx.model.functions.values():
        if fn.language != "plpgsql" or not fn.sql:
            continue
        try:
            parsed = parser.parse_plpgsql(fn.sql)
        except Exception:  # unparsable body: reported through unresolved elsewhere
            continue
        if _typed_arguments_only(fn):
            continue  # every format() argument is a non-text parameter (date, int, uuid, ...)
        body_offset = fn.sql.find(fn.body) if fn.body else 0
        body_line = fn.line + fn.sql[: max(body_offset, 0)].count("\n")
        for item in parsed:
            for expr, lineno in _dynamic_queries(item.raw):
                if not unsafe_dynamic_query(expr):
                    continue
                line = body_line + lineno - 1
                yield SchemaHit(
                    fn.file,
                    min(max(line, fn.line), fn.end_line),
                    fn.end_line,
                    f"Function {fn.schema}.{fn.name} builds an EXECUTE query by concatenating or "
                    "formatting (%s) values into the SQL text.",
                    trace=(TraceStep(fn.file, line, "sink", f"EXECUTE {expr.strip()[:80]}"),),
                    symbol=f"{fn.schema}.{fn.name}",
                    confidence=Confidence.MEDIUM,
                )


# --- grants -------------------------------------------------------------------------------------


def _dangerous(role: str, privileges: frozenset[str]) -> frozenset[str]:
    if role in ("anon", "public"):
        return privileges & WRITE_PRIVILEGES
    if role == "authenticated" and privileges >= ALL_TABLE_PRIVILEGES:
        return privileges
    return frozenset()


def grant_broad(ctx: CheckContext) -> Iterator[SchemaHit]:
    exposed = exposed_schemas(ctx.model)
    for ev in ctx.model.grant_events:
        danger = _dangerous(ev.role, ev.privileges)
        tables = [
            t for name in ev.tables
            if (t := ctx.model.tables.get(name)) is not None and t.schema in exposed
        ]  # fmt: skip
        still_granted = [
            t for t in tables
            if any(g.role == ev.role and danger & g.privileges for g in t.grants)
        ]  # fmt: skip
        if danger and still_granted:
            names = ", ".join(t.qualified_name for t in still_granted[:3])
            protected = all(t.rls_enabled for t in still_granted)  # RLS still gates the rows
            yield SchemaHit(
                ev.file,
                ev.line,
                ev.end_line,
                f"GRANT {'ALL' if danger >= WRITE_PRIVILEGES else ', '.join(sorted(danger))} on "
                f"{names} to {ev.role}: the API role can write without any policy-level limit "
                "besides RLS.",
                symbol=f"{ev.role}:{names}",
                confidence=Confidence.LOW if protected else None,
            )


def default_priv(ctx: CheckContext) -> Iterator[SchemaHit]:
    exposed = set(exposed_schemas(ctx.model))
    for dp in ctx.model.default_privileges:
        if dp.baseline or not dp.is_grant or dp.object_type != "table":
            continue
        if dp.schema is not None and dp.schema not in exposed:
            continue
        risky = [g for g in dp.grantees if _dangerous(g, dp.privileges)]
        if risky:
            platform_default = dp.role in ("postgres", "supabase_admin")  # `db pull` boilerplate
            yield SchemaHit(
                dp.file,
                dp.line,
                dp.end_line,
                f"ALTER DEFAULT PRIVILEGES grants write access on every future table to "
                f"{', '.join(risky)}.",
                symbol=f"default:{dp.schema}:{','.join(risky)}",
                confidence=Confidence.LOW if platform_default else None,
            )


# --- storage ------------------------------------------------------------------------------------


def storage_public(ctx: CheckContext) -> Iterator[SchemaHit]:
    for b in ctx.model.buckets.values():
        if b.public and SENSITIVE_BUCKET.search(b.name):
            yield SchemaHit(
                b.file,
                b.line,
                b.end_line,
                f"Storage bucket {b.name!r} is public but its name suggests sensitive files.",
                symbol=f"bucket:{b.name}",
            )


def storage_policy(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table, p in _policies(ctx):
        if table.qualified_name != "storage.objects" or not p.permissive:
            continue
        if p.command not in WRITE_COMMANDS or not _client_facing(p):
            continue
        text = f"{p.using_expr or ''} {p.check_expr or ''}"
        if STORAGE_OWNERSHIP.search(text):
            continue
        yield SchemaHit(
            p.file,
            p.line,
            p.end_line,
            f"Policy {p.name!r} on storage.objects allows {p.command.upper()} for "
            f"{', '.join(p.roles)} without checking who owns the object.",
            trace=_trace_policy(table, p, "no ownership condition"),
            symbol=f"storage.objects:{p.name}",
        )


# --- seed and config ----------------------------------------------------------------------------

_SEED_RE = re.compile(r"(?:^|/)supabase/seeds?(?:/[^/]+)?\.sql$|(?:^|/)supabase/seed[^/]*\.sql$")
_PASSWORD_COLUMNS = {"encrypted_password", "password", "raw_password"}


class _SecretFinder(Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.found = False

    def visit_FuncCall(self, ancestors: Any, node: Any) -> None:
        name = [str(n.sval).lower() for n in (node.funcname or ())]
        if name and name[-1] == "crypt" and node.args:
            first = node.args[0]
            if isinstance(first, A.A_Const) and isinstance(first.val, A.String):
                self.found = True

    def visit_DefElem(self, ancestors: Any, node: Any) -> None:
        if node.defname == "password" and isinstance(node.arg, A.String):
            self.found = True


def seed_secret(ctx: CheckContext) -> Iterator[SchemaHit]:
    paths = getattr(ctx.repo, "paths", [])
    parser = PglastParser()
    for path in sorted(p for p in paths if _SEED_RE.search(p)):
        for stmt in parser.parse_lenient(ctx.repo.read_text(path)).statements:
            finder = _SecretFinder()
            finder(stmt.node)
            literal_column = False
            if isinstance(stmt.node, A.InsertStmt) and isinstance(
                stmt.node.selectStmt, A.SelectStmt
            ):
                columns = [c.name for c in (stmt.node.cols or [])]
                for row in stmt.node.selectStmt.valuesLists or []:
                    for col, expr in zip(columns, row, strict=False):
                        if (
                            col in _PASSWORD_COLUMNS
                            and isinstance(expr, A.A_Const)
                            and isinstance(expr.val, A.String)
                        ):
                            literal_column = True
            if finder.found or literal_column:
                yield SchemaHit(
                    path,
                    stmt.line,
                    stmt.end_line,
                    "Seed data contains a hard-coded password. It ships with every environment "
                    "the seed is applied to.",
                    symbol=f"{path}:{stmt.line}",
                )


def config_signup(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in ctx.model.configs.values():
        auth = doc.data.get("auth", {})
        email = auth.get("email", {})
        signup = auth.get("enable_signup", True) and email.get("enable_signup", True)
        if (
            signup
            and email.get("enable_confirmations", False) is False
            and "enable_confirmations" in email
        ):  # noqa: E501
            line = doc.lines.get(("auth", "email", "enable_confirmations"), 1)
            yield SchemaHit(
                doc.path,
                line,
                line,
                "Email sign-ups are open and confirmation is disabled: anyone can create verified "
                "accounts with addresses they do not own. (supabase init writes this as a local "
                "development default; it matters when the file is pushed to a hosted project.)",
                symbol=f"{doc.path}:auth.email",
                confidence=Confidence.LOW,
            )


def schema_drift(ctx: CheckContext) -> Iterator[SchemaHit]:
    """Differences between the migrations and a dump of the live database."""
    live = ctx.model.drift_source
    if live is None:
        return
    exposed = exposed_schemas(ctx.model)
    keys = sorted(k for k in {*ctx.model.tables, *live.tables} if k.split(".", 1)[0] in exposed)
    for key in keys:
        mig, db = ctx.model.tables.get(key), live.tables.get(key)
        if mig is not None and mig.external:
            mig = None
        if mig is not None and db is None:
            yield SchemaHit(
                mig.file, mig.line, mig.end_line,
                f"Table {key} is in the migrations but not in the database dump "
                "(migration not applied?).",
                symbol=key,
            )  # fmt: skip
        elif mig is None and db is not None:
            state = "RLS enabled" if db.rls_enabled else "RLS DISABLED"
            yield SchemaHit(
                db.file, db.line, db.end_line,
                f"Table {key} exists in the database but in no migration ({state}); it was "
                "probably created in the dashboard and is not reviewed.",
                symbol=key,
            )  # fmt: skip
        elif mig is not None and db is not None:
            if mig.rls_enabled != db.rls_enabled:
                wrong = "disabled" if not db.rls_enabled else "enabled"
                yield SchemaHit(
                    mig.rls_file, mig.rls_line, mig.rls_end_line,
                    f"RLS on {key} is {wrong} in the live database but the migrations say the "
                    "opposite.",
                    trace=(
                        TraceStep(db.rls_file, db.rls_line, "schema", f"database: RLS {wrong}"),
                    ),
                    symbol=key,
                )  # fmt: skip
            only_db = sorted({p.name for p in db.policies} - {p.name for p in mig.policies})
            only_mig = sorted({p.name for p in mig.policies} - {p.name for p in db.policies})
            if only_db or only_mig:
                parts = []
                if only_db:
                    parts.append(f"only in the database: {', '.join(only_db)}")
                if only_mig:
                    parts.append(f"only in the migrations: {', '.join(only_mig)}")
                yield SchemaHit(
                    mig.file, mig.line, mig.end_line,
                    f"Policies on {key} differ ({'; '.join(parts)}).",
                    symbol=f"{key}:policies",
                )  # fmt: skip


_PRIVILEGED_CODE = re.compile(
    r"SERVICE_ROLE|service_role|serviceRole|[Ss]upabaseAdmin|SUPABASE_DB_URL|postgres\(|\.rpc\("
    r"|(?<!Array)(?<!Buffer)(?<!Object)\.from\(\s*['\"`]"
)


def _function_is_privileged(ctx: CheckContext, config_path: str, name: str) -> bool:
    """Does the function's source use a service_role client or touch the database?"""
    base = config_path.rsplit("/", 1)[0] if "/" in config_path else ""
    prefix = f"{base}/functions/{name}/" if base else f"functions/{name}/"
    for path in getattr(ctx.repo, "paths", []):
        if path.startswith(prefix) and path.endswith((".ts", ".js", ".tsx", ".mjs")):
            try:
                if _PRIVILEGED_CODE.search(ctx.repo.read_text(path)):
                    return True
            except OSError:
                continue
    return False


def edge_no_jwt(ctx: CheckContext) -> Iterator[SchemaHit]:
    """Edge functions declared with ``verify_jwt = false`` in supabase/config.toml."""
    for doc in ctx.model.configs.values():
        functions = doc.data.get("functions", {})
        if not isinstance(functions, dict):
            continue
        for name, cfg in sorted(functions.items()):
            if isinstance(cfg, dict) and cfg.get("verify_jwt") is False:
                line = doc.lines.get(("functions", name, "verify_jwt"), 1)
                privileged = _function_is_privileged(ctx, doc.path, name)
                yield SchemaHit(
                    doc.path,
                    line,
                    line,
                    f"Edge function {name!r} is publicly invokable: JWT verification is disabled. "
                    "Anyone on the internet can call it; make sure it authenticates callers itself "
                    "(e.g. a webhook signature)."
                    + (
                        " It uses a service_role client or queries the database."
                        if privileged
                        else ""
                    ),
                    symbol=f"{doc.path}:functions.{name}",
                    confidence=Confidence.MEDIUM if privileged else Confidence.LOW,
                )
