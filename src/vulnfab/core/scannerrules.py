"""Execution of ``scanner`` rules: text scanners that look at file contents directly."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from vulnfab.core.models import Confidence, Finding, Severity, SourceFile
from vulnfab.core.rules import ScannerRule

ALLOWED_SCANNER_PREFIX = "vulnfab."
SNIPPET_LIMIT = 300


class ScannerError(Exception):
    pass


@dataclass
class ScannerHit:
    file: str
    line: int
    end_line: int
    message: str = ""
    snippet: str = ""
    symbol: str = ""
    confidence: Confidence | None = None
    severity: Severity | None = None


@dataclass
class ScannerContext:
    files: list[SourceFile]
    rule: ScannerRule
    settings: dict[str, Any] = field(default_factory=dict)  # e.g. {"osv_db": path}


ScannerFn = Callable[[ScannerContext], Iterable[ScannerHit]]


def load_scanner(target: str) -> ScannerFn:
    module_name, _, func = target.partition(":")
    if not module_name.startswith(ALLOWED_SCANNER_PREFIX):
        raise ScannerError(
            f"scanner module {module_name!r} is not allowed (must be inside vulnfab)"
        )
    try:
        fn: Any = getattr(importlib.import_module(module_name), func)
    except (ImportError, AttributeError) as exc:
        raise ScannerError(f"cannot load scanner {target!r}: {exc}") from exc
    if not callable(fn):
        raise ScannerError(f"{target!r} is not callable")
    return fn  # type: ignore[no-any-return]


def run_scanner_rules(
    rules: Iterable[ScannerRule],
    files: list[SourceFile],
    settings: dict[str, Any] | None = None,
) -> list[tuple[Finding, str]]:
    out: list[tuple[Finding, str]] = []
    for rule in rules:
        if not rule.enabled:
            continue
        selected = [f for f in files if not rule.languages or f.language in rule.languages]
        for hit in load_scanner(rule.scanner)(ScannerContext(selected, rule, settings or {})):
            snippet = hit.snippet
            out.append(
                (
                    Finding(
                        rule_id=rule.id,
                        title=rule.display_title,
                        cwe=tuple(rule.cwe),
                        owasp=rule.owasp,
                        severity=hit.severity or rule.severity,
                        confidence=hit.confidence or rule.confidence,
                        tier=rule.tier,
                        file=hit.file,
                        line=hit.line,
                        end_line=hit.end_line,
                        snippet=snippet
                        if len(snippet) <= SNIPPET_LIMIT
                        else snippet[:SNIPPET_LIMIT] + "...",
                        fix=rule.fix,
                        message=hit.message or rule.message,
                    ),
                    hit.symbol,
                )
            )
    return out
