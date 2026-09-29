"""Build the final-state SchemaModel from Postgres/Supabase migrations (WP-3.2, 3.3, 3.5).

Migrations are applied in order (file name order = timestamp order). Statements the builder does
not understand are ignored; statements it cannot analyse (DO blocks, unparsable SQL) are recorded
as ``Unresolved`` so they show up in the coverage report.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from pglast import ast as A
from pglast import enums as E
from pglast.stream import RawStream

from vulnfab.core.models import (
    Bucket,
    Column,
    DefaultPrivilege,
    Function,
    Grant,
    Policy,
    SchemaModel,
    Table,
    Unresolved,
    View,
)
from vulnfab.core.sqlparser import PglastParser, SqlParser, Statement

DEFAULT_SCHEMA = "public"
ALL_TABLE_PRIVILEGES = frozenset(
    {"select", "insert", "update", "delete", "truncate", "references", "trigger"}
)
PLATFORM_ROLES = ("anon", "authenticated", "service_role")
BASELINE_ASSUMPTION = (
    "Supabase default privileges assumed: tables created in schema public are granted ALL to "
    "anon, authenticated and service_role (RLS is the only access control)."
)


def deparse(node: Any) -> str | None:
    if node is None:
        return None
    try:
        return str(RawStream()(node))
    except Exception:  # deparse is best effort; never fail a scan on it
        return None


def _role_name(spec: Any) -> str:
    if spec.roletype == E.RoleSpecType.ROLESPEC_PUBLIC:
        return "public"
    if spec.roletype == E.RoleSpecType.ROLESPEC_CSTRING:
        return str(spec.rolename)
    return str(spec.roletype.name).removeprefix("ROLESPEC_").lower()


def _privileges(privs: Any) -> frozenset[str]:
    if not privs:
        return ALL_TABLE_PRIVILEGES
    names = {str(p.priv_name).lower() for p in privs if p.priv_name}
    return ALL_TABLE_PRIVILEGES if "all" in names else frozenset(names)


def _qualified(rv: Any) -> tuple[str, str]:
    return (rv.schemaname or DEFAULT_SCHEMA, rv.relname)


def _strings(items: Any) -> list[str]:
    return [str(i.sval) for i in (items or []) if isinstance(i, A.String)]


def _not_null(col: Any) -> bool:
    if col.is_not_null:
        return True
    return any(
        isinstance(c, A.Constraint)
        and c.contype in (E.ConstrType.CONSTR_NOTNULL, E.ConstrType.CONSTR_PRIMARY)
        for c in (col.constraints or [])
    )


def baseline_default_privileges() -> list[DefaultPrivilege]:
    return [
        DefaultPrivilege(
            role="postgres",
            schema=DEFAULT_SCHEMA,
            object_type="table",
            privileges=ALL_TABLE_PRIVILEGES,
            grantees=PLATFORM_ROLES,
            baseline=True,
        )
    ]


class SchemaBuilder:
    def __init__(self, parser: SqlParser | None = None) -> None:
        self.parser = parser or PglastParser()
        self.model = SchemaModel(default_privileges=baseline_default_privileges())
        self.model.assumptions.append(BASELINE_ASSUMPTION)

    # --- entry points -----------------------------------------------------------------------

    def apply_file(self, path: str, sql: str) -> None:
        result = self.parser.parse_lenient(sql)
        for issue in result.issues:
            self.model.unresolved.append(
                Unresolved("sql_parse_error", path, issue.line, issue.message.split(",")[0])
            )
        for stmt in result.statements:
            self.apply(stmt, path)

    def apply(self, stmt: Statement, path: str) -> None:
        handler = getattr(self, f"_on_{stmt.kind}", None)
        if handler is not None:
            handler(stmt, path)

    # --- helpers ----------------------------------------------------------------------------

    def _table(self, schema: str, name: str) -> Table | None:
        return self.model.tables.get(f"{schema}.{name}")

    def _table_or_external(self, schema: str, name: str) -> Table:
        table = self._table(schema, name)
        if table is None:
            table = Table(name=name, schema=schema, external=True)
            self.model.tables[table.qualified_name] = table
        return table

    def _set_grant(
        self,
        table: Table,
        role: str,
        privileges: frozenset[str],
        *,
        grant: bool,
        file: str,
        line: int,
        with_grant: bool = False,
        default: bool = False,
    ) -> None:
        existing = next((g for g in table.grants if g.role == role), None)
        if grant:
            if existing is None:
                table.grants.append(
                    Grant(role, privileges, with_grant, file, line, inherited_default=default)
                )
            else:
                merged = existing.privileges | privileges
                table.grants[table.grants.index(existing)] = replace(
                    existing,
                    privileges=merged,
                    with_grant=existing.with_grant or with_grant,
                    file=file if not default else existing.file,
                    line=line if not default else existing.line,
                    inherited_default=existing.inherited_default and default,
                )
        elif existing is not None:
            remaining = existing.privileges - privileges
            if remaining:
                table.grants[table.grants.index(existing)] = replace(existing, privileges=remaining)
            else:
                table.grants.remove(existing)

    def _apply_default_privileges(self, table: Table, file: str, line: int) -> None:
        for dp in self.model.default_privileges:
            if dp.object_type != "table" or (dp.schema is not None and dp.schema != table.schema):
                continue
            for grantee in dp.grantees:
                self._set_grant(
                    table, grantee, dp.privileges, grant=dp.is_grant, file=file, line=line,
                    default=True,
                )  # fmt: skip

    def _new_table(
        self, schema: str, name: str, stmt: Statement, path: str, columns: list[Column]
    ) -> Table:
        table = Table(
            name=name, schema=schema, columns=columns, file=path, line=stmt.line,
            end_line=stmt.end_line, rls_file=path, rls_line=stmt.line, rls_end_line=stmt.end_line,
        )  # fmt: skip
        self.model.tables[table.qualified_name] = table
        self._apply_default_privileges(table, path, stmt.line)
        return table

    # --- tables -----------------------------------------------------------------------------

    def _on_CreateStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.relation.relpersistence == "t":
            return
        schema, name = _qualified(n.relation)
        if n.if_not_exists and self._table(schema, name) is not None:
            return
        columns = [
            Column(
                name=str(e.colname),
                type=deparse(e.typeName) or "",
                nullable=not _not_null(e),
            )
            for e in (n.tableElts or [])
            if isinstance(e, A.ColumnDef)
        ]
        self._new_table(schema, name, stmt, path, columns)

    def _on_CreateTableAsStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.objtype == E.ObjectType.OBJECT_TABLE and n.into is not None:
            schema, name = _qualified(n.into.rel)
            self._new_table(schema, name, stmt, path, [])

    def _on_AlterTableStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.objtype != E.ObjectType.OBJECT_TABLE:
            return
        schema, name = _qualified(n.relation)
        table = self._table(schema, name)
        for cmd in n.cmds or []:
            kind = cmd.subtype
            if kind in (
                E.AlterTableType.AT_EnableRowSecurity,
                E.AlterTableType.AT_DisableRowSecurity,
            ):
                table = table or self._table_or_external(schema, name)
                table.rls_enabled = kind == E.AlterTableType.AT_EnableRowSecurity
                table.rls_file, table.rls_line, table.rls_end_line = path, stmt.line, stmt.end_line
            elif kind in (
                E.AlterTableType.AT_ForceRowSecurity,
                E.AlterTableType.AT_NoForceRowSecurity,
            ):
                table = table or self._table_or_external(schema, name)
                table.rls_forced = kind == E.AlterTableType.AT_ForceRowSecurity
            elif kind == E.AlterTableType.AT_AddColumn and table is not None:
                col = cmd.def_
                if isinstance(col, A.ColumnDef):
                    table.columns.append(
                        Column(str(col.colname), deparse(col.typeName) or "", not _not_null(col))
                    )
            elif kind == E.AlterTableType.AT_DropColumn and table is not None:
                table.columns = [c for c in table.columns if c.name != cmd.name]

    def _on_RenameStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        rtype = n.renameType
        if rtype in (E.ObjectType.OBJECT_TABLE, E.ObjectType.OBJECT_VIEW) and n.relation:
            schema, name = _qualified(n.relation)
            store: dict[str, Any] = (
                self.model.tables if rtype == E.ObjectType.OBJECT_TABLE else self.model.views
            )
            obj = store.pop(f"{schema}.{name}", None)
            if obj is not None:
                obj.name = n.newname
                store[f"{schema}.{n.newname}"] = obj
                if isinstance(obj, Table):
                    for policy in obj.policies:
                        policy.table = n.newname
        elif rtype == E.ObjectType.OBJECT_COLUMN and n.relation:
            table = self._table(*_qualified(n.relation))
            if table is not None:
                for col in table.columns:
                    if col.name == n.subname:
                        col.name = n.newname
        elif rtype == E.ObjectType.OBJECT_POLICY and n.relation:
            table = self._table(*_qualified(n.relation))
            if table is not None:
                for policy in table.policies:
                    if policy.name == n.subname:
                        policy.name = n.newname
        elif rtype == E.ObjectType.OBJECT_SCHEMA:
            self._move_schema(n.subname, n.newname)

    def _move_schema(self, old: str, new: str) -> None:
        stores: list[dict[str, Any]] = [
            self.model.tables, self.model.views, self.model.functions,
        ]  # fmt: skip
        for store in stores:
            for key in [k for k in store if k.startswith(f"{old}.")]:
                obj = store.pop(key)
                obj.schema = new
                rest = key[len(old) + 1 :]
                store[f"{new}.{rest}"] = obj

    def _on_AlterObjectSchemaStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.relation is None:
            return
        schema, name = _qualified(n.relation)
        if n.objectType == E.ObjectType.OBJECT_TABLE:
            store: dict[str, Any] = self.model.tables
        elif n.objectType == E.ObjectType.OBJECT_VIEW:
            store = self.model.views
        else:
            return
        obj = store.pop(f"{schema}.{name}", None)
        if obj is not None:
            obj.schema = n.newschema
            store[f"{n.newschema}.{name}"] = obj

    def _on_DropStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        kind = n.removeType
        for obj in n.objects or []:
            if kind in (E.ObjectType.OBJECT_TABLE, E.ObjectType.OBJECT_VIEW):
                names = _strings(obj)
                schema, name = (
                    (names[-2], names[-1]) if len(names) >= 2 else (DEFAULT_SCHEMA, names[-1])
                )  # noqa: E501
                store: dict[str, Any] = (
                    self.model.tables if kind == E.ObjectType.OBJECT_TABLE else self.model.views
                )
                store.pop(f"{schema}.{name}", None)
            elif kind == E.ObjectType.OBJECT_POLICY:
                names = _strings(obj)
                if len(names) >= 2:
                    table_schema = names[-3] if len(names) >= 3 else DEFAULT_SCHEMA
                    table = self._table(table_schema, names[-2])
                    if table is not None:
                        table.policies = [p for p in table.policies if p.name != names[-1]]
            elif kind == E.ObjectType.OBJECT_SCHEMA and isinstance(obj, A.String):
                for store2 in (self.model.tables, self.model.views, self.model.functions):
                    for key in [k for k in store2 if k.startswith(f"{obj.sval}.")]:
                        del store2[key]
            elif kind == E.ObjectType.OBJECT_FUNCTION and isinstance(obj, A.ObjectWithArgs):
                names = _strings(obj.objname)
                schema, name = (
                    (names[-2], names[-1]) if len(names) >= 2 else (DEFAULT_SCHEMA, names[-1])
                )  # noqa: E501
                nargs = len(obj.objargs or [])
                self.model.functions.pop(f"{schema}.{name}({nargs})", None)

    # --- policies ---------------------------------------------------------------------------

    def _on_CreatePolicyStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        schema, name = _qualified(n.table)
        table = self._table_or_external(schema, name)
        if schema == "storage" and name == "objects":
            table.rls_enabled = True  # managed by the platform with RLS on
        roles = tuple(_role_name(r) for r in (n.roles or [])) or ("public",)
        table.policies.append(
            Policy(
                name=n.policy_name,
                table=name,
                permissive=bool(n.permissive),
                command=n.cmd_name,
                roles=roles,
                using_expr=deparse(n.qual),
                check_expr=deparse(n.with_check),
                using_node=n.qual,
                check_node=n.with_check,
                file=path,
                line=stmt.line,
                end_line=stmt.end_line,
                sql=stmt.sql,
            )
        )

    def _on_AlterPolicyStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        table = self._table(*_qualified(n.table))
        if table is None:
            return
        for policy in table.policies:
            if policy.name != n.policy_name:
                continue
            if n.roles:
                policy.roles = tuple(_role_name(r) for r in n.roles)
            if n.qual is not None:
                policy.using_expr, policy.using_node = deparse(n.qual), n.qual
            if n.with_check is not None:
                policy.check_expr, policy.check_node = deparse(n.with_check), n.with_check
            policy.file, policy.line, policy.end_line = path, stmt.line, stmt.end_line
            policy.sql = stmt.sql

    # --- grants -----------------------------------------------------------------------------

    def _on_GrantStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.objtype != E.ObjectType.OBJECT_TABLE:
            return
        privileges = _privileges(n.privileges)
        roles = [_role_name(g) for g in (n.grantees or [])]
        if n.targtype == E.GrantTargetType.ACL_TARGET_ALL_IN_SCHEMA:
            schemas = _strings(n.objects)
            targets = [t for t in self.model.tables.values() if t.schema in schemas]
        else:
            targets = [
                self._table_or_external(*_qualified(rv))
                for rv in (n.objects or [])
                if isinstance(rv, A.RangeVar)
            ]
        for table in targets:
            for role in roles:
                self._set_grant(
                    table, role, privileges, grant=bool(n.is_grant), file=path, line=stmt.line,
                    with_grant=bool(n.grant_option),
                )  # fmt: skip

    def _on_AlterDefaultPrivilegesStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        role: str | None = None
        schema: str | None = None
        for opt in n.options or []:
            if opt.defname == "roles" and opt.arg:
                role = _role_name(opt.arg[0])
            elif opt.defname == "schemas" and opt.arg:
                schema = _strings(opt.arg)[0]
        action = n.action
        object_type = {
            E.ObjectType.OBJECT_TABLE: "table",
            E.ObjectType.OBJECT_SEQUENCE: "sequence",
            E.ObjectType.OBJECT_FUNCTION: "function",
        }.get(action.objtype, "other")
        self.model.default_privileges.append(
            DefaultPrivilege(
                role=role,
                schema=schema,
                object_type=object_type,
                privileges=_privileges(action.privileges),
                grantees=tuple(_role_name(g) for g in (action.grantees or [])),
                is_grant=bool(action.is_grant),
                file=path,
                line=stmt.line,
                end_line=stmt.end_line,
            )
        )

    # --- functions and views ------------------------------------------------------------------

    @staticmethod
    def _function_options(options: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for opt in options or []:
            if opt.defname == "security":
                out["security_definer"] = bool(opt.arg.boolval)
            elif opt.defname == "language":
                out["language"] = str(opt.arg.sval).lower()
            elif opt.defname == "as":
                out["body"] = "\n".join(_strings(opt.arg))
            elif (
                opt.defname == "set"
                and isinstance(opt.arg, A.VariableSetStmt)
                and opt.arg.name == "search_path"
            ):
                if opt.arg.kind == E.VariableSetKind.VAR_SET_VALUE:
                    parts = [
                        str(a.val.sval) for a in (opt.arg.args or []) if isinstance(a.val, A.String)
                    ]
                    out["search_path"] = ", ".join(parts)
                elif opt.arg.kind == E.VariableSetKind.VAR_SET_CURRENT:
                    out["search_path"] = "(current)"
                else:
                    out["search_path"] = None
                    out["search_path_reset"] = True
        return out

    def _on_CreateFunctionStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        names = _strings(n.funcname)
        schema, name = (names[-2], names[-1]) if len(names) >= 2 else (DEFAULT_SCHEMA, names[-1])
        opts = self._function_options(n.options)
        params = n.parameters or []
        fn = Function(
            name=name,
            schema=schema,
            security_definer=opts.get("security_definer", False),
            search_path=opts.get("search_path"),
            language=opts.get("language", "sql"),
            body=opts.get("body", ""),
            file=path,
            line=stmt.line,
            end_line=stmt.end_line,
            sql=stmt.sql,
            param_names=tuple(p.name for p in params if getattr(p, "name", None)),
        )
        self.model.functions[f"{schema}.{name}({len(params)})"] = fn

    def _on_AlterFunctionStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.func is None:
            return
        names = _strings(n.func.objname)
        schema, name = (names[-2], names[-1]) if len(names) >= 2 else (DEFAULT_SCHEMA, names[-1])
        nargs = len(n.func.objargs or [])
        fn = self.model.functions.get(f"{schema}.{name}({nargs})")
        if fn is None:
            return
        opts = self._function_options(n.actions)
        if "security_definer" in opts:
            fn.security_definer = opts["security_definer"]
        if "search_path" in opts or opts.get("search_path_reset"):
            fn.search_path = opts.get("search_path")

    def _on_ViewStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        schema, name = _qualified(n.view)
        invoker = False
        for opt in n.options or []:
            if opt.defname == "security_invoker":
                arg = opt.arg
                value = arg.sval if isinstance(arg, A.String) else str(getattr(arg, "boolval", ""))
                invoker = str(value).lower() in ("true", "on", "1", "yes")
        self.model.views[f"{schema}.{name}"] = View(
            name=name, schema=schema, security_invoker=invoker, definition=stmt.sql, file=path,
            line=stmt.line, end_line=stmt.end_line,
        )  # fmt: skip

    # --- storage buckets and DO blocks --------------------------------------------------------

    def _on_InsertStmt(self, stmt: Statement, path: str) -> None:
        n = stmt.node
        if n.relation.schemaname != "storage" or n.relation.relname != "buckets":
            return
        select = n.selectStmt
        if not isinstance(select, A.SelectStmt) or not select.valuesLists:
            self.model.unresolved.append(
                Unresolved(
                    "dynamic_bucket", path, stmt.line, "storage.buckets insert is not VALUES"
                )
            )
            return
        columns = [c.name for c in (n.cols or [])]
        for row in select.valuesLists:
            values: dict[str, Any] = {}
            for col, expr in zip(columns, row, strict=False):
                if isinstance(expr, A.A_Const) and not expr.isnull:
                    val = expr.val
                    values[col] = (
                        val.sval if isinstance(val, A.String) else getattr(val, "boolval", None)
                    )
            name = values.get("name") or values.get("id")
            if not isinstance(name, str):
                self.model.unresolved.append(
                    Unresolved("dynamic_bucket", path, stmt.line, "bucket name is not a constant")
                )
                continue
            is_public = values.get("public") is True
            self.model.buckets[name] = Bucket(name, is_public, path, stmt.line, stmt.end_line)

    def _on_DoStmt(self, stmt: Statement, path: str) -> None:
        self.model.unresolved.append(
            Unresolved("do_block", path, stmt.line, "DO block contents are not analysed")
        )
