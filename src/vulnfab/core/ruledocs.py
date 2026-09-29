"""Human-readable rule descriptions: `vulnfab explain` and the generated rule reference."""
# ruff: noqa: E501

from __future__ import annotations

from typing import Any

OWASP_URL = "https://owasp.org/Top10/"
CWE_URL = "https://cwe.mitre.org/data/definitions/{number}.html"
KIND_HELP = {
    "pattern": "Syntax pattern (tree-sitter); flags code that has the shape described.",
    "taint": "Data-flow rule; reports only when untrusted data reaches the sink (trace included).",
    "schema": "Reads the database/config model built from migrations or settings.",
    "scanner": "Text scanner over files (secrets, env files, templates).",
    "crosscheck": "Relates code facts (queries, routes) to the schema or auth model.",
}


def cwe_link(cwe: str) -> str:
    number = cwe.removeprefix("CWE-")
    return f"[{cwe}]({CWE_URL.format(number=number)})"


def _list(values: list[str]) -> str:
    return ", ".join(f"`{v}`" for v in values) if values else "—"


def explain_text(rule: Any) -> str:
    """Plain text for the terminal."""
    lines = [
        f"{rule.id}  —  {rule.display_title}",
        f"  stack: {rule.stack}   kind: {rule.kind}   severity: {rule.severity.value}   "
        f"confidence: {rule.confidence.value}" + (f"   tier: {rule.tier}" if rule.tier else ""),
        f"  {KIND_HELP.get(rule.kind, '')}",
        "",
        f"  {rule.message}",
    ]
    if rule.cwe or rule.owasp:
        lines.append(
            f"  references: {', '.join(rule.cwe)} {('OWASP ' + rule.owasp) if rule.owasp else ''}".rstrip()
        )
    if rule.fix:
        lines += ["", f"  how to fix: {rule.fix}"]
    if getattr(rule, "supersedes", None):
        lines.append(f"  replaces (when the data flow is confirmed): {', '.join(rule.supersedes)}")
    if rule.kind == "taint":
        lines += [
            "",
            f"  sources: {', '.join(rule.sources)}",
            f"  sinks: {', '.join(rule.sinks)}",
        ]
        if rule.sanitizers:
            lines.append(f"  sanitizers: {', '.join(rule.sanitizers)}")
    lines.append(f"  suppress one finding with: # nosec: {rule.id}")
    return "\n".join(lines)


def reference_markdown(rules: list[Any], version: str) -> str:
    """The generated rule reference (docs/rules.md)."""
    by_stack: dict[str, list[Any]] = {}
    for rule in sorted(rules, key=lambda r: r.id):
        by_stack.setdefault(rule.stack, []).append(rule)
    out = [
        "# Referensi rule",
        "",
        f"Dibuat otomatis oleh `scripts/gen_rule_docs.py` dari rule pack (vulnfab {version}).",
        "**Jangan edit tangan**; perbarui rule YAML lalu jalankan skripnya. CI memeriksa kesinkronan.",
        "",
        f"Total: {len(rules)} rule. Tingkat: **A** struktural/pasti, **B** pola kepemilikan (IDOR; "
        "confidence maksimum medium), **C** kandidat semantik (tersembunyi secara default).",
        "",
        "Menekan satu temuan: komentar `# nosec: <rule-id>` di barisnya, `per_file_ignores` di "
        "`.vulnfab.yml`, atau baseline.",
        "",
    ]
    for stack in sorted(by_stack):
        items = by_stack[stack]
        out += [
            f"## Stack `{stack}` ({len(items)} rule)",
            "",
            "| Rule | Jenis | Severity | Confidence | Tier | CWE |",
            "|---|---|---|---|---|---|",
        ]
        for r in items:
            out.append(
                f"| [`{r.id}`](#{r.id}) | {r.kind} | {r.severity.value} | {r.confidence.value} | "
                f"{r.tier or '—'} | {', '.join(cwe_link(c) for c in r.cwe) or '—'} |"
            )
        out.append("")
        for r in items:
            out += [f"### {r.id}", "", f"**{r.display_title}** — {r.message}", ""]
            out.append(f"- Jenis: {r.kind} — {KIND_HELP.get(r.kind, '')}")
            if r.fix:
                out.append(f"- Perbaikan: {r.fix}")
            if r.owasp:
                out.append(f"- OWASP: [{r.owasp}]({OWASP_URL})")
            if getattr(r, "supersedes", None):
                out.append(f"- Menggantikan (bila alur data terbukti): {_list(list(r.supersedes))}")
            if r.kind == "taint":
                out.append(f"- Sumber: {_list(list(r.sources))}")
                out.append(f"- Sink: {_list(list(r.sinks))}")
                if r.sanitizers:
                    out.append(f"- Sanitizer: {_list(list(r.sanitizers))}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"
