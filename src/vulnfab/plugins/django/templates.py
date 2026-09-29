"""Scanners for Django templates (``.html``): unsafe output and missing CSRF tokens (WP-6.3)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.scannerrules import ScannerContext, ScannerHit

_COMMENT_INLINE = re.compile(r"\{#.*?#\}", re.DOTALL)
_COMMENT_BLOCK = re.compile(r"\{%\s*comment\b.*?\{%\s*endcomment\s*%\}", re.DOTALL)
_VARIABLE = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_AUTOESCAPE_OFF = re.compile(r"\{%\s*autoescape\s+off\s*%\}")
_FORM_OPEN = re.compile(r"<form\b[^>]*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_BLOCK = re.compile(
    r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.IGNORECASE | re.DOTALL
)

ESCAPING_FILTERS = {
    "escape", "force_escape", "e", "linebreaks", "linebreaksbr", "striptags", "urlize",
    "urlizetrunc", "floatformat", "date", "time", "length", "escapejs", "json_script",
    "slugify", "urlencode", "iriencode", "intcomma", "filesizeformat", "pluralize",
}  # fmt: skip
JS_SAFE_FILTERS = {"escapejs", "json_script", "tojson", "int", "floatformat", "length", "date"}
TRUSTED_BASES = re.compile(
    r"^(form(\.\w+)*(\.as_\w+)?|block\.super|csrf_token|forloop\.\w+|messages)$"
)


def is_template(sf: SourceFile) -> bool:
    return (
        "{{" in sf.text
        or "{%" in sf.text
        or "{#" in sf.text
        or f"/{sf.path}".find("/templates/") >= 0
    )


def blank_comments(text: str) -> str:
    """Replace template comments by spaces, keeping newlines so line numbers stay valid."""

    def blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    return _COMMENT_BLOCK.sub(blank, _COMMENT_INLINE.sub(blank, text))


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def split_filters(expression: str) -> tuple[str, list[str]]:
    """``a.b|f:"x|y"|g`` -> (``a.b``, [``f``, ``g``]); quotes are respected."""
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in expression:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    base = parts[0].strip()
    filters = [p.split(":", 1)[0].strip() for p in parts[1:]]
    return base, filters


def _literal(base: str) -> bool:
    return bool(base) and (base[0] in "'\"" or base[0].isdigit())


def safe_filter(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if not is_template(sf):
            continue
        text = blank_comments(sf.text)
        for m in _VARIABLE.finditer(text):
            base, filters = split_filters(m.group(1))
            if "safe" not in filters and "safeseq" not in filters:
                continue
            index = min(filters.index(f) for f in ("safe", "safeseq") if f in filters)
            if _literal(base) or any(f in ESCAPING_FILTERS for f in filters[:index]):
                continue
            line = _line(text, m.start())
            yield ScannerHit(
                sf.path,
                line,
                _line(text, m.end()),
                f"'{{{{ {base}|safe }}}}' disables HTML escaping: if the value can contain user "
                "input this is stored/reflected XSS.",
                snippet=m.group(0).strip(),
                symbol=f"{sf.path}:{base}",
                confidence=Confidence.LOW if TRUSTED_BASES.match(base) else Confidence.MEDIUM,
            )


def autoescape_off(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if not is_template(sf):
            continue
        text = blank_comments(sf.text)
        for m in _AUTOESCAPE_OFF.finditer(text):
            line = _line(text, m.start())
            yield ScannerHit(
                sf.path,
                line,
                line,
                "{% autoescape off %} turns off HTML escaping for the whole block.",
                snippet=m.group(0),
                symbol=f"{sf.path}:autoescape",
            )


def form_without_csrf(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if not is_template(sf):
            continue
        text = blank_comments(sf.text)
        for m in _FORM_OPEN.finditer(text):
            tag = m.group(0)
            method = re.search(r"method\s*=\s*[\"']?(\w+)", tag, re.IGNORECASE)
            if not method or method.group(1).lower() != "post":
                continue
            action = re.search(r"action\s*=\s*[\"']?(https?:)?//", tag, re.IGNORECASE)
            if action and not re.search(r"action\s*=\s*[\"']?\{\{", tag):
                continue  # posts to another site: Django's token must not be sent there
            end = text.find("</form", m.end())
            body = text[m.end() : end if end >= 0 else len(text)]
            if "csrf_token" in body or "csrf_token" in tag:
                continue
            include = bool(re.search(r"\{%\s*(include|extends)\b", body))
            line = _line(text, m.start())
            yield ScannerHit(
                sf.path,
                line,
                line,
                "This POST form has no {% csrf_token %}: with CsrfViewMiddleware the submit is "
                "rejected, and if the token is missing on purpose the form is open to CSRF."
                + (" (An included template may add it.)" if include else ""),
                snippet=" ".join(tag.split())[:120],
                symbol=f"{sf.path}:form",
                confidence=Confidence.LOW if include else Confidence.MEDIUM,
            )


def script_context_output(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if not is_template(sf):
            continue
        text = blank_comments(sf.text)
        for block in _SCRIPT_BLOCK.finditer(text):
            if "src=" in block.group("attrs").lower() or "application/json" in block.group("attrs"):
                continue
            body_start = block.start("body")
            for var in _VARIABLE.finditer(block.group("body")):
                base, filters = split_filters(var.group(1))
                if _literal(base) or any(f in JS_SAFE_FILTERS for f in filters):
                    continue
                offset = body_start + var.start()
                line = _line(text, offset)
                yield ScannerHit(
                    sf.path,
                    line,
                    line,
                    f"'{{{{ {base} }}}}' is printed inside a <script> block; HTML escaping does "
                    "not protect a JavaScript context. Use |escapejs or |json_script.",
                    snippet=var.group(0).strip(),
                    symbol=f"{sf.path}:{base}",
                    confidence=Confidence.LOW,
                )
