"""Check functions for Laravel rules (see rules/laravel/*.yml)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence, TraceStep
from vulnfab.core.schemarules import CheckContext, SchemaHit
from vulnfab.plugins.laravel.routes import PUBLIC_NAME


def _trace(entry) -> tuple[TraceStep, ...]:  # type: ignore[no-untyped-def]
    if not entry.route_file:
        return ()
    return (TraceStep(entry.route_file, entry.route_line, "call", f"route {entry.route}"),)


def route_no_auth(ctx: CheckContext) -> Iterator[SchemaHit]:
    """Routes that read or change data with no auth middleware and no inline user check."""
    seen: set[tuple[str, str, str]] = set()
    for entry in ctx.entrypoints:
        if entry.auth is None or entry.auth.required is not False:
            continue
        action = entry.handler.rsplit("@", 1)[-1]
        if PUBLIC_NAME.match(action) or entry.handler.startswith("closure@") and not entry.traits:
            continue
        key = (entry.file, entry.handler, entry.route)
        if key in seen:
            continue
        seen.add(key)
        if "writes" in entry.traits:
            what, confidence = "changes data", Confidence.MEDIUM
        elif "reads-data" in entry.traits and entry.params:
            what, confidence = "returns data selected by a URL parameter", Confidence.MEDIUM
        else:
            continue
        yield SchemaHit(
            entry.file,
            entry.line,
            entry.line,
            f"Route {entry.route} ({entry.handler}) {what} but has no auth middleware and the "
            "handler never inspects the current user.",
            trace=_trace(entry),
            symbol=f"{entry.file}:{entry.handler}",
            confidence=confidence,
        )


def csrf_exempt_route(ctx: CheckContext) -> Iterator[SchemaHit]:
    seen: set[str] = set()
    for entry in ctx.entrypoints:
        if "csrf-exempt" not in entry.traits or entry.route in seen:
            continue
        seen.add(entry.route)
        writes = "writes" in entry.traits
        yield SchemaHit(
            entry.route_file or entry.file,
            entry.route_line or entry.line,
            entry.route_line or entry.line,
            f"Route {entry.route} is excluded from CSRF verification"
            + (" and changes data" if writes else "")
            + ".",
            trace=_trace(entry),
            symbol=f"{entry.file}:{entry.handler}:{entry.route}",
            confidence=Confidence.MEDIUM if writes else Confidence.LOW,
        )


PRIVILEGED_COLUMN = re.compile(
    r"^(is_?admin|admin|is_?staff|is_?superuser|is_?super_?admin|role|roles|role_id|permissions?|"
    r"balance|credits?|is_?verified|email_verified_at|verified|is_?active|banned|approved)$",
    re.I,
)


def _model_hit(table, message: str, line: int, confidence: Confidence) -> SchemaHit:  # type: ignore[no-untyped-def]
    file = table.extras.get("model_file", table.file)
    return SchemaHit(
        file,
        line or table.extras.get("model_line", 1),
        line or table.extras.get("model_line", 1),
        message,
        symbol=f"{file}:{table.extras.get('model', table.name)}",
        confidence=confidence,
    )


def guarded_empty(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table in ctx.model.tables.values():
        if table.extras.get("guarded") == [] and table.extras.get("model"):
            privileged = [c.name for c in table.columns if PRIVILEGED_COLUMN.match(c.name)]
            yield _model_hit(
                table,
                f"{table.extras['model']} sets $guarded = []: every column is mass-assignable, so "
                "create()/update()/fill() with request data can set any attribute"
                + (f" (including {', '.join(privileged)})." if privileged else "."),
                table.extras.get("guarded_line", 0),
                Confidence.HIGH if privileged else Confidence.MEDIUM,
            )


def fillable_privileged(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table in ctx.model.tables.values():
        fillable = table.extras.get("fillable")
        if not fillable or not table.extras.get("model"):
            continue
        bad = [f for f in fillable if PRIVILEGED_COLUMN.match(f)]
        if bad:
            yield _model_hit(
                table,
                f"{table.extras['model']}::$fillable contains {', '.join(bad)}: a request that "
                "reaches create()/update() with all input can grant itself these attributes.",
                table.extras.get("model_line", 0),
                Confidence.MEDIUM,
            )


def hidden_missing(ctx: CheckContext) -> Iterator[SchemaHit]:
    for table in ctx.model.tables.values():
        if not table.extras.get("model"):
            continue
        hidden = set(table.extras.get("hidden") or [])
        sensitive = [c.name for c in table.columns if c.sensitive_hint and c.name not in hidden]
        if sensitive:
            yield _model_hit(
                table,
                f"{table.extras['model']} does not hide {', '.join(sensitive)} from serialization: "
                "returning the model (or a collection) from a route/API leaks them in JSON.",
                table.extras.get("model_line", 0),
                Confidence.LOW if table.extras.get("hidden") is not None else Confidence.MEDIUM,
            )
