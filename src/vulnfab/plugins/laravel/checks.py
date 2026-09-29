"""Check functions for Laravel rules (see rules/laravel/*.yml)."""

from __future__ import annotations

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
