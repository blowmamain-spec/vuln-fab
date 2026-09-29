"""Execution of ``schema`` rules (check functions or safe conditions) against a SchemaModel."""

from __future__ import annotations

import ast
import importlib
import string
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from vulnfab.core.models import (
    Confidence,
    DataAccess,
    Entrypoint,
    Finding,
    SchemaModel,
    TraceStep,
)
from vulnfab.core.rules import SCHEMA_CONDITION_NAMES, CrosscheckRule, SchemaRule
from vulnfab.core.safeexpr import compile_expression
from vulnfab.plugins.base import RepoView

ALLOWED_CHECK_PREFIX = "vulnfab."
SNIPPET_LIMIT = 300


class CheckError(Exception):
    pass


@dataclass
class SchemaHit:
    file: str
    line: int
    end_line: int
    detail: str = ""
    trace: tuple[TraceStep, ...] = ()
    symbol: str = ""
    confidence: Confidence | None = None
    snippet: str = ""


@dataclass
class CheckContext:
    model: SchemaModel
    repo: RepoView
    rule: SchemaRule | CrosscheckRule
    extras: dict[str, Any] = field(default_factory=dict)
    facts: list[DataAccess] = field(default_factory=list)
    entrypoints: list[Entrypoint] = field(default_factory=list)

    def snippet(self, file: str, line: int, end_line: int) -> str:
        try:
            lines = self.repo.read_text(file).split("\n")
        except (OSError, KeyError):
            return ""
        text = "\n".join(lines[max(line - 1, 0) : max(end_line, line)]).strip()
        return text if len(text) <= SNIPPET_LIMIT else text[:SNIPPET_LIMIT] + "..."


CheckFn = Callable[[CheckContext], Iterable[SchemaHit]]


def load_check(target: str) -> CheckFn:
    module_name, _, func = target.partition(":")
    if not module_name.startswith(ALLOWED_CHECK_PREFIX):
        raise CheckError(f"check module {module_name!r} is not allowed (must be inside vulnfab)")
    try:
        module = importlib.import_module(module_name)
        fn = getattr(module, func)
    except (ImportError, AttributeError) as exc:
        raise CheckError(f"cannot load check {target!r}: {exc}") from exc
    if not callable(fn):
        raise CheckError(f"{target!r} is not callable")
    return fn  # type: ignore[no-any-return]


class _SafeFormatter(string.Formatter):
    """str.format that refuses private attributes and indexing."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> tuple[Any, str]:
        first, *rest = field_name.split(".")
        if "[" in field_name or any(part.startswith("_") for part in [first, *rest]):
            raise CheckError(f"illegal message field {field_name!r}")
        obj = kwargs[first]
        for part in rest:
            obj = getattr(obj, part)
        return obj, first


def format_message(template: str, **objects: Any) -> str:
    try:
        return _SafeFormatter().vformat(template, (), objects)
    except (KeyError, AttributeError, CheckError):
        return template


def _names(expression: str) -> set[str]:
    return {
        n.id
        for n in ast.walk(ast.parse(expression.strip(), mode="eval"))
        if isinstance(n, ast.Name)
    }


def _condition_hits(rule: SchemaRule, ctx: CheckContext) -> list[SchemaHit]:
    assert rule.condition is not None
    names = _names(rule.condition)
    fn = compile_expression(rule.condition, SCHEMA_CONDITION_NAMES)
    model = ctx.model
    hits: list[SchemaHit] = []

    def hit(file: str, line: int, end: int, symbol: str, **objs: Any) -> None:
        detail = format_message(rule.message, **objs)
        hits.append(SchemaHit(file, line, end, detail, symbol=symbol))

    if "config" in names:
        for doc in model.configs.values():
            if fn(config=doc.data):
                hit(doc.path, 1, 1, doc.path, config=doc.data)
    elif "policy" in names:
        for table in model.tables.values():
            for policy in table.policies:
                if fn(
                    **{k: v for k, v in {"policy": policy, "table": table}.items() if k in names}
                ):
                    hit(
                        policy.file,
                        policy.line,
                        policy.end_line,
                        f"{table.qualified_name}:{policy.name}",
                        policy=policy,
                        table=table,
                    )  # noqa: E501
    elif "function" in names:
        for func in model.functions.values():
            if fn(function=func):
                hit(
                    func.file, func.line, func.end_line, f"{func.schema}.{func.name}", function=func
                )
    elif "view" in names:
        for view in model.views.values():
            if fn(view=view):
                hit(view.file, view.line, view.end_line, f"{view.schema}.{view.name}", view=view)
    elif "bucket" in names:
        for bucket in model.buckets.values():
            if fn(bucket=bucket):
                hit(bucket.file, bucket.line, bucket.end_line, bucket.name, bucket=bucket)
    else:
        uses_rls = "rls_enabled" in rule.condition or "rls_forced" in rule.condition
        for table in model.tables.values():
            if table.external or not fn(table=table):
                continue
            if uses_rls:
                hit(
                    table.rls_file,
                    table.rls_line,
                    table.rls_end_line,
                    table.qualified_name,
                    table=table,
                )  # noqa: E501
            else:
                hit(table.file, table.line, table.end_line, table.qualified_name, table=table)
    return hits


def run_schema_rules(
    rules: Iterable[SchemaRule], model: SchemaModel, repo: RepoView
) -> list[tuple[Finding, str]]:
    out: list[tuple[Finding, str]] = []
    for rule in rules:
        if not rule.enabled:
            continue
        ctx = CheckContext(model, repo, rule)
        if rule.check is not None:
            hits = list(load_check(rule.check)(ctx))
        else:
            hits = _condition_hits(rule, ctx)
        out.extend(_to_findings(rule, ctx, hits))
    return out


def run_crosscheck_rules(
    rules: Iterable[CrosscheckRule],
    facts: list[DataAccess],
    model: SchemaModel,
    repo: RepoView,
    entrypoints: list[Entrypoint] | None = None,
) -> list[tuple[Finding, str]]:
    """Rules that relate code-level facts (`DataAccess`, `Entrypoint`) to the schema model."""
    out: list[tuple[Finding, str]] = []
    for rule in rules:
        if not rule.enabled:
            continue
        ctx = CheckContext(model, repo, rule, facts=facts, entrypoints=entrypoints or [])
        out.extend(_to_findings(rule, ctx, list(load_check(rule.check)(ctx))))
    return out


def _to_findings(
    rule: SchemaRule | CrosscheckRule, ctx: CheckContext, hits: list[SchemaHit]
) -> list[tuple[Finding, str]]:
    return [
        (
            Finding(
                rule_id=rule.id,
                title=rule.display_title,
                cwe=tuple(rule.cwe),
                owasp=rule.owasp,
                severity=rule.severity,
                confidence=h.confidence or rule.confidence,
                tier=rule.tier,
                file=h.file,
                line=h.line,
                end_line=h.end_line,
                snippet=h.snippet or ctx.snippet(h.file, h.line, h.end_line),
                trace=h.trace,
                fix=rule.fix,
                message=h.detail or rule.message,
            ),
            h.symbol,
        )
        for h in hits
    ]
