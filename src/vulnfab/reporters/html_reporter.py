"""Self-contained HTML report. Every dynamic value is escaped; the page has no scripts."""
# ruff: noqa: E501

from __future__ import annotations

from html import escape
from itertools import groupby

from vulnfab import __version__
from vulnfab.core.models import Finding, Severity
from vulnfab.core.report import ScanResult, sort_key

CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5b6470;--line:#d8dde3;--card:#f6f8fa;
--critical:#b00020;--high:#d24a00;--medium:#a06a00;--low:#3f6f9f;--info:#5b6470}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e8ea;--muted:#9aa4af;
--line:#2c333a;--card:#1c2126;--critical:#ff6b81;--high:#ff9a5c;--medium:#e6b450;--low:#7fb2e5;--info:#9aa4af}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.meta,.muted{color:var(--muted)}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.counts span{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:4px 10px}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:10px 12px;display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}
.sev{font-weight:600;text-transform:uppercase;font-size:.75rem}
.sev.critical{color:var(--critical)}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}
.sev.low{color:var(--low)}.sev.info{color:var(--info)}
.body{padding:0 12px 12px;border-top:1px solid var(--line)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
code{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
ol{padding-left:20px}
@media print{details{break-inside:avoid}}
"""

SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _finding(f: Finding) -> str:
    trace = ""
    if f.trace:
        steps = "".join(
            f"<li><code>{_e(s.file)}:{_e(s.line)}</code> <span class='muted'>{_e(s.kind)}</span> "
            f"{_e(s.detail)}</li>"
            for s in f.trace
        )
        trace = f"<h3>Path</h3><ol>{steps}</ol>"
    fix = f"<p><strong>Fix:</strong> {_e(f.fix)}</p>" if f.fix else ""
    hops = (
        f"<p class='muted'>Confidence lowered: {_e(f.unresolved_hops)} unresolved call(s) on the path.</p>"
        if f.unresolved_hops
        else ""
    )
    cwe = ", ".join(_e(c) for c in f.cwe)
    tier = f" · tier {_e(f.tier)}" if f.tier else ""
    return (
        "<details>"
        f"<summary><span class='sev {_e(f.severity.value)}'>{_e(f.severity.value)}</span>"
        f"<strong>{_e(f.title)}</strong>"
        f"<code>{_e(f.file)}:{_e(f.line)}</code>"
        f"<span class='muted'>{_e(f.rule_id)} · {_e(f.confidence.value)} confidence{tier}</span></summary>"
        "<div class='body'>"
        f"<p>{_e(f.message or f.title)}</p>"
        f"<pre><code>{_e(f.snippet)}</code></pre>"
        f"{trace}{fix}{hops}"
        f"<p class='muted'>{cwe}{' · ' if cwe and f.owasp else ''}{_e(f.owasp or '')}"
        f" · fingerprint {_e(f.fingerprint)}</p>"
        "</div></details>"
    )


def render(result: ScanResult) -> str:
    findings = sorted(result.findings, key=lambda f: (SEVERITIES.index(f.severity), *sort_key(f)))
    counts = "".join(
        f"<span><span class='sev {s.value}'>{s.value}</span> {sum(1 for f in findings if f.severity is s)}</span>"
        for s in SEVERITIES
    )
    groups = []
    for severity, items in groupby(findings, key=lambda f: f.severity):
        groups.append(
            f"<h2>{_e(severity.value.capitalize())}</h2>" + "".join(_finding(f) for f in items)
        )
    cov = result.coverage
    unresolved = "".join(
        f"<li><code>{_e(u.file)}:{_e(u.line)}</code> {_e(u.kind)} {_e(u.detail)}</li>"
        for u in cov.unresolved[:200]
    )
    assumptions = "".join(f"<li>{_e(a)}</li>" for a in cov.assumptions)
    notes = (
        f"<li>{_e(cov.files_scanned)} files scanned, {_e(len(cov.files_skipped))} skipped, "
        f"{_e(cov.hidden_low_confidence)} low-confidence finding(s) hidden, "
        f"{_e(cov.suppressed_nosec + cov.suppressed_baseline + cov.suppressed_config)} suppressed.</li>"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>vulnfab report</title>"
        f"<style>{CSS}</style></head><body><main>"
        f"<h1>vulnfab report</h1><p class='meta'>{_e(result.target)} · stacks: "
        f"{_e(', '.join(result.stacks) or 'none')} · vulnfab {_e(__version__)}</p>"
        f"<div class='counts'>{counts}</div>"
        + ("".join(groups) if groups else "<p>No findings at the current confidence threshold.</p>")
        + "<h2>Coverage &amp; limitations</h2><ul>"
        + notes
        + assumptions
        + "</ul>"
        + (f"<h3>Unresolved constructs</h3><ul>{unresolved}</ul>" if unresolved else "")
        + "</main></body></html>\n"
    )
