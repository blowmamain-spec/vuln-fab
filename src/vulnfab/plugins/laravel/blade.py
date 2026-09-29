"""Scanners for Blade templates: unescaped output, missing @csrf, raw PHP echo (WP-7.3)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence
from vulnfab.core.scannerrules import ScannerContext, ScannerHit

_COMMENT = re.compile(r"\{\{--.*?--\}\}", re.DOTALL)
_VERBATIM = re.compile(r"@verbatim\b.*?@endverbatim", re.DOTALL)
_RAW = re.compile(r"\{!!(.*?)!!\}", re.DOTALL)
_FORM_OPEN = re.compile(r"<form\b[^>]*>", re.IGNORECASE | re.DOTALL)
_PHP_ECHO = re.compile(r"<\?=\s*(.*?)\s*\?>|<\?php\s+echo\s+(.*?);?\s*\?>", re.DOTALL)
_PHP_BLOCK = re.compile(r"@php\b(.*?)@endphp", re.DOTALL)

TRUSTED_CALL = re.compile(
    r"^\s*(?:csrf_field|method_field|csrf_token|route|url|asset|secure_asset|mix|vite|__|trans|"
    r"trans_choice|e|htmlspecialchars|htmlentities|strip_tags|json_encode|nl2br\(\s*e|"
    r"Purifier::clean|clean|Form::\w+|Html::\w+|Js::from)\s*\(|"
    r"^\s*\$(?:slot|attributes|errors|component)\b|->(?:links|render|toHtml)\s*\(",
    re.S,
)
SAFE_WRAPPERS = (
    "e(",
    "htmlspecialchars(",
    "htmlentities(",
    "strip_tags(",
    "Purifier::clean(",
    "clean(",
)
PLAIN_LITERAL = re.compile(r"""^\s*(["']).*\1\s*$""", re.S)


def blank(text: str) -> str:
    def spaces(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    return _VERBATIM.sub(spaces, _COMMENT.sub(spaces, text))


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def unescaped_output(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        text = blank(sf.text)
        for m in _RAW.finditer(text):
            expr = m.group(1).strip()
            if PLAIN_LITERAL.match(expr) or any(expr.startswith(w) for w in SAFE_WRAPPERS):
                continue
            trusted = bool(TRUSTED_CALL.search(expr))
            line = _line(text, m.start())
            yield ScannerHit(
                sf.path,
                line,
                _line(text, m.end()),
                f"'{{!! {expr[:60]} !!}}' prints without HTML escaping: if the value can hold user "
                "input this is stored/reflected XSS. Use {{ }} or sanitise first.",
                snippet=m.group(0).strip()[:120],
                symbol=f"{sf.path}:{expr[:40]}",
                confidence=Confidence.LOW if trusted else Confidence.MEDIUM,
            )


def form_without_csrf(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        text = blank(sf.text)
        for m in _FORM_OPEN.finditer(text):
            tag = m.group(0)
            method = re.search(r"method\s*=\s*[\"']?(\w+)", tag, re.IGNORECASE)
            if not method or method.group(1).lower() == "get":
                continue
            if re.search(r"action\s*=\s*[\"']?https?://", tag, re.IGNORECASE):
                continue
            end = text.find("</form", m.end())
            body = text[m.end() : end if end >= 0 else len(text)]
            if re.search(r"@csrf\b|csrf_field\(|csrf_token\(|name\s*=\s*[\"']_token", body):
                continue
            include = bool(re.search(r"@include\b|<x-", body))
            line = _line(text, m.start())
            yield ScannerHit(
                sf.path,
                line,
                line,
                "This form submits with a state-changing method but has no @csrf: with "
                "VerifyCsrfToken the request is rejected; if CSRF checking was relaxed the form is "
                "open to cross-site requests."
                + (" (An included view may add it.)" if include else ""),
                snippet=" ".join(tag.split())[:120],
                symbol=f"{sf.path}:form",
                confidence=Confidence.LOW if include else Confidence.MEDIUM,
            )


def php_echo(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        text = blank(sf.text)
        matches = [
            (m.start(), (m.group(1) or m.group(2) or "").strip()) for m in _PHP_ECHO.finditer(text)
        ]
        for block in _PHP_BLOCK.finditer(text):
            for echo in re.finditer(r"\becho\s+(.*?);", block.group(1), re.DOTALL):
                matches.append((block.start(1) + echo.start(), echo.group(1).strip()))
        for offset, expr in matches:
            if (
                not expr
                or PLAIN_LITERAL.match(expr)
                or any(expr.startswith(w) for w in SAFE_WRAPPERS)
            ):
                continue
            yield ScannerHit(
                sf.path,
                _line(text, offset),
                _line(text, offset),
                f"Raw PHP echo of '{expr[:50]}' inside a Blade view skips Blade's escaping.",
                snippet=expr[:120],
                symbol=f"{sf.path}:{expr[:40]}",
                confidence=Confidence.LOW if TRUSTED_CALL.search(expr) else Confidence.MEDIUM,
            )
