"""Effective access of a role to a table (WP-3.4; semantics in docs/spec.md section 5).

Rules of PostgreSQL row level security that are modelled:
- a role needs the table privilege (GRANT) first; ``public`` grants apply to everyone;
- ``service_role`` bypasses RLS; with RLS disabled everything granted is accessible;
- RLS enabled and no applicable policy -> deny;
- permissive policies are OR-ed, restrictive policies are AND-ed on top;
- policy expressions are evaluated conservatively (literal true/false, auth.uid() ownership,
  auth.role() checks, IS NOT NULL); anything else is UNKNOWN.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from pglast import ast as A
from pglast import enums as E
from pglast.visitors import Visitor

from vulnfab.core.models import Policy, Table

COMMANDS = ("select", "insert", "update", "delete")
PLATFORM_ROLES = ("anon", "authenticated", "service_role")


class AccessKind(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Access:
    kind: AccessKind
    reason: str = ""
    owner_columns: tuple[str, ...] = ()
    policies: tuple[str, ...] = field(default=())

    @property
    def is_open(self) -> bool:
        """Definitely accessible without any row condition."""
        return self.kind is AccessKind.ALLOW


def allow(reason: str = "") -> Access:
    return Access(AccessKind.ALLOW, reason)


def deny(reason: str = "") -> Access:
    return Access(AccessKind.DENY, reason)


def unknown(reason: str = "") -> Access:
    return Access(AccessKind.UNKNOWN, reason)


def conditional(reason: str, owner: tuple[str, ...] = ()) -> Access:
    return Access(AccessKind.CONDITIONAL, reason, owner)


# --- expression evaluation ----------------------------------------------------------------------


def _unwrap(node: Any) -> Any:
    """Look through ``(select f())`` sub-selects and type casts."""
    while True:
        if isinstance(node, A.TypeCast):
            node = node.arg
        elif (
            isinstance(node, A.SubLink)
            and node.subLinkType == E.SubLinkType.EXPR_SUBLINK
            and isinstance(node.subselect, A.SelectStmt)
            and node.subselect.targetList
            and len(node.subselect.targetList) == 1
            and node.subselect.fromClause is None
        ):
            node = node.subselect.targetList[0].val
        else:
            return node


def _func_name(node: Any) -> tuple[str, ...] | None:
    node = _unwrap(node)
    if isinstance(node, A.FuncCall):
        return tuple(str(n.sval).lower() for n in (node.funcname or ()))
    return None


def _is_uid(node: Any) -> bool:
    node = _unwrap(node)
    name = _func_name(node)
    if name in (("auth", "uid"), ("uid",)):
        return True
    return (
        name == ("current_setting",)
        and bool(node.args)
        and isinstance(node.args[0], A.A_Const)
        and "jwt.claim.sub" in str(getattr(node.args[0].val, "sval", ""))
    )


def _is_role_fn(node: Any) -> bool:
    return _func_name(node) in (("auth", "role"), ("role",))


def _column(node: Any) -> str | None:
    node = _unwrap(node)
    if isinstance(node, A.ColumnRef):
        fields = node.fields or ()
        return str(fields[-1].sval) if fields and isinstance(fields[-1], A.String) else None
    return None


def _const_str(node: Any) -> str | None:
    if isinstance(node, A.A_Const) and not node.isnull and isinstance(node.val, A.String):
        return str(node.val.sval)
    return None


class _Mentions(Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.funcs: set[tuple[str, ...]] = set()

    def visit_FuncCall(self, ancestors: Any, node: Any) -> None:
        self.funcs.add(tuple(str(n.sval).lower() for n in node.funcname))


def mentions_function(node: Any, *names: tuple[str, ...]) -> bool:
    if node is None:
        return False
    v = _Mentions()
    v(node)
    return any(n in v.funcs for n in names)


def eval_expr(node: Any, role: str) -> Access:
    if node is None:
        return allow("no expression")
    node = _unwrap(node)
    if isinstance(node, A.A_Const):
        val = getattr(node.val, "boolval", None)
        if val is True:
            return allow("literal true")
        if val is False:
            return deny("literal false")
        return unknown("non-boolean constant")
    if isinstance(node, A.BoolExpr):
        parts = [eval_expr(a, role) for a in (node.args or ())]
        if node.boolop == E.BoolExprType.NOT_EXPR:
            only = parts[0]
            if only.kind is AccessKind.ALLOW:
                return deny("negated true")
            if only.kind is AccessKind.DENY:
                return allow("negated false")
            return unknown("negation")
        return _and(parts) if node.boolop == E.BoolExprType.AND_EXPR else _or(parts)
    if isinstance(node, A.NullTest):
        if _is_uid(node.arg):
            if node.nulltesttype == E.NullTestType.IS_NOT_NULL:
                if role == "anon":
                    return deny("anon has no auth.uid()")
                return allow("auth.uid() IS NOT NULL (any signed-in user)")
            return unknown("auth.uid() IS NULL")
        return unknown("null test")
    if isinstance(node, A.A_Expr):
        return _eval_a_expr(node, role)
    if isinstance(node, A.ColumnRef):
        return conditional(f"row condition on {_column(node)}")
    if mentions_function(node, ("auth", "jwt")):
        return conditional("JWT claim condition")
    return unknown(type(node).__name__)


def _eval_a_expr(node: A.A_Expr, role: str) -> Access:
    op = str(node.name[0].sval) if node.name else ""
    left, right = node.lexpr, node.rexpr
    if node.kind == E.A_Expr_Kind.AEXPR_IN and _is_role_fn(left):
        values = {_const_str(c) for c in (right or [])}
        return allow("auth.role() matches") if role in values else deny("auth.role() differs")
    if node.kind == E.A_Expr_Kind.AEXPR_OP and op == "=":
        for a, b in ((left, right), (right, left)):
            if _is_uid(a):
                col = _column(b)
                if col:
                    if role == "anon":
                        return deny("anon has no auth.uid()")
                    return conditional(f"owner: auth.uid() = {col}", (col,))
            if _is_role_fn(a):
                value = _const_str(_unwrap(b))
                if value is not None:
                    return allow("auth.role() matches") if value == role else deny("role differs")
        if isinstance(left, A.A_Const) and isinstance(right, A.A_Const):
            same = getattr(left.val, "ival", left.val) == getattr(right.val, "ival", right.val)
            return allow("constant comparison") if same else deny("constant comparison")
    if mentions_function(node, ("auth", "jwt")):
        return conditional("JWT claim condition")
    if _column(left) or _column(right):
        return conditional("row condition")
    return unknown("expression")


def _merge_owner(parts: list[Access]) -> tuple[str, ...]:
    seen: list[str] = []
    for p in parts:
        seen.extend(c for c in p.owner_columns if c not in seen)
    return tuple(seen)


def _and(parts: list[Access]) -> Access:
    if any(p.kind is AccessKind.DENY for p in parts):
        return deny("AND with a denying term")
    cond = [p for p in parts if p.kind is AccessKind.CONDITIONAL]
    if cond:
        return conditional("; ".join(p.reason for p in cond), _merge_owner(cond))
    if any(p.kind is AccessKind.UNKNOWN for p in parts):
        return unknown("AND with an unknown term")
    return allow("all terms allow")


def _or(parts: list[Access]) -> Access:
    if any(p.kind is AccessKind.ALLOW for p in parts):
        return allow("OR with an allowing term")
    if any(p.kind is AccessKind.UNKNOWN for p in parts):
        return unknown("OR with an unknown term")
    cond = [p for p in parts if p.kind is AccessKind.CONDITIONAL]
    if cond:
        return conditional("; ".join(p.reason for p in cond), _merge_owner(cond))
    return deny("all terms deny")


# --- policies and tables ------------------------------------------------------------------------


def policy_expression(policy: Policy, command: str, role: str) -> Access:
    """Result of one policy for one command."""
    using, check = policy.using_node, policy.check_node
    if using is None and check is None:
        return allow("policy has no expression")
    if command in ("select", "delete"):
        return eval_expr(using if using is not None else check, role)
    if command == "insert":
        return eval_expr(check if check is not None else using, role)
    # update: existing row must satisfy USING and the new row WITH CHECK (defaults to USING)
    return _and(
        [
            eval_expr(using if using is not None else check, role),
            eval_expr(check if check is not None else using, role),
        ]
    )


def applies_to(policy: Policy, command: str, role: str) -> bool:
    return policy.command in ("all", command) and ("public" in policy.roles or role in policy.roles)


def _has_privilege(table: Table, role: str, privilege: str) -> bool:
    return any(g.role in (role, "public") and privilege in g.privileges for g in table.grants)


def effective_access(table: Table, role: str, command: str) -> Access:
    """Can ``role`` perform ``command`` (select/insert/update/delete) on ``table``?"""
    if command not in COMMANDS:
        raise ValueError(f"unknown command {command!r}")
    if not _has_privilege(table, role, command):
        return deny(f"no {command.upper()} privilege for {role}")
    if role == "service_role":
        return allow("service_role bypasses RLS")
    if not table.rls_enabled:
        return allow("RLS is disabled")
    applicable = [p for p in table.policies if applies_to(p, command, role)]
    permissive = [p for p in applicable if p.permissive]
    restrictive = [p for p in applicable if not p.permissive]
    if not permissive:
        return deny("RLS enabled and no applicable permissive policy")
    granted = _or([policy_expression(p, command, role) for p in permissive])
    if restrictive:
        granted = _and([granted, *(policy_expression(p, command, role) for p in restrictive)])
    names = tuple(p.name for p in applicable)
    return Access(granted.kind, granted.reason, granted.owner_columns, names)
