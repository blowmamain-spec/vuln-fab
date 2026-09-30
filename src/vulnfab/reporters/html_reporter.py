"""Self-contained HTML report. Every dynamic value is escaped.

The default page has no scripts. ``interactive=True`` (format ``html-triage``) adds one static inline
script for filtering and recording verdicts; it contains no scan data and the page carries a CSP
that forbids every network access.
"""
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
.bar{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center;z-index:2}
.bar input,.bar select,.bar button,.verdict input{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.verdict{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:10px}
.verdict button{cursor:pointer;font:inherit;padding:3px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.verdict button.on{outline:2px solid var(--medium);font-weight:600}
.badge{font-size:.75rem;border:1px solid var(--line);border-radius:10px;padding:0 8px}
details.judged{opacity:.65}
@media print{details{break-inside:avoid}}
"""

SCRIPT = """
(function(){
var body=document.body,target=body.getAttribute('data-target')||'',key='vulnfab-triage:'+target;
var items=[].slice.call(document.querySelectorAll('details[data-fp]'));
var state={};
try{state=JSON.parse(localStorage.getItem(key)||'{}')}catch(e){state={}}
function save(){try{localStorage.setItem(key,JSON.stringify(state))}catch(e){}}
var q=document.getElementById('q'),sev=document.getElementById('sev'),rule=document.getElementById('rule'),
hide=document.getElementById('hide'),who=document.getElementById('who'),count=document.getElementById('count');
try{who.value=localStorage.getItem(key+':who')||''}catch(e){}
function paint(d){var fp=d.getAttribute('data-fp'),v=state[fp]||{},b=d.querySelector('.badge');
 b.textContent=v.verdict?v.verdict.toUpperCase():'';d.classList.toggle('judged',!!v.verdict);
 [].forEach.call(d.querySelectorAll('.verdict button'),function(x){x.classList.toggle('on',x.getAttribute('data-v')===v.verdict)});
 d.querySelector('.verdict input').value=v.note||''}
function filter(){var n=0,t=q.value.toLowerCase();
 items.forEach(function(d){var fp=d.getAttribute('data-fp'),ok=true;
  if(sev.value&&d.getAttribute('data-sev')!==sev.value)ok=false;
  if(rule.value&&d.getAttribute('data-rule')!==rule.value)ok=false;
  if(hide.checked&&state[fp]&&state[fp].verdict)ok=false;
  if(t&&d.textContent.toLowerCase().indexOf(t)<0)ok=false;
  d.style.display=ok?'':'none';if(ok)n++});
 var done=Object.keys(state).filter(function(k){return state[k].verdict}).length;
 count.textContent=n+' shown · '+done+'/'+items.length+' judged'}
items.forEach(function(d){var fp=d.getAttribute('data-fp');paint(d);
 [].forEach.call(d.querySelectorAll('.verdict button'),function(b){b.addEventListener('click',function(){
  var v=b.getAttribute('data-v'),cur=state[fp]||{};
  state[fp]={verdict:cur.verdict===v?'':v,note:cur.note||''};if(!state[fp].verdict&&!state[fp].note)delete state[fp];
  save();paint(d);filter()})});
 d.querySelector('.verdict input').addEventListener('input',function(e){
  var cur=state[fp]||{verdict:''};cur.note=e.target.value;state[fp]=cur;save()})});
[q,sev,rule,hide].forEach(function(el){el.addEventListener('input',filter)});
who.addEventListener('input',function(){try{localStorage.setItem(key+':who',who.value)}catch(e){}});
document.getElementById('export').addEventListener('click',function(){
 var out={target:target,reviewer:who.value,verdicts:{}};
 Object.keys(state).sort().forEach(function(k){if(state[k].verdict)out.verdicts[k]={verdict:state[k].verdict,note:state[k].note||''}});
 var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(out,null,2)+'\\n'],{type:'application/json'}));
 a.download='vulnfab-verdicts.json';document.body.appendChild(a);a.click();a.remove()});
filter();
})();
"""

SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _finding(f: Finding, interactive: bool = False) -> str:
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
    verdict = (
        "<div class='verdict'><button type='button' data-v='tp'>TP</button>"
        "<button type='button' data-v='fp'>FP</button><button type='button' data-v='dup'>DUP</button>"
        "<input type='text' placeholder='reason (one sentence)' size='40'></div>"
        if interactive
        else ""
    )
    attrs = (
        f" data-fp='{_e(f.fingerprint)}' data-sev='{_e(f.severity.value)}' data-rule='{_e(f.rule_id)}'"
        if interactive
        else ""
    )
    badge = "<span class='badge'></span>" if interactive else ""
    return (
        f"<details{attrs}>"
        f"<summary><span class='sev {_e(f.severity.value)}'>{_e(f.severity.value)}</span>{badge}"
        f"<strong>{_e(f.title)}</strong>"
        f"<code>{_e(f.file)}:{_e(f.line)}</code>"
        f"<span class='muted'>{_e(f.rule_id)} · {_e(f.confidence.value)} confidence{tier}</span></summary>"
        "<div class='body'>"
        f"<p>{_e(f.message or f.title)}</p>"
        f"<pre><code>{_e(f.snippet)}</code></pre>"
        f"{trace}{fix}{hops}{verdict}"
        f"<p class='muted'>{cwe}{' · ' if cwe and f.owasp else ''}{_e(f.owasp or '')}"
        f" · fingerprint {_e(f.fingerprint)}</p>"
        "</div></details>"
    )


def render_triage(result: ScanResult) -> str:
    return render(result, interactive=True)


def render(result: ScanResult, interactive: bool = False) -> str:
    findings = sorted(result.findings, key=lambda f: (SEVERITIES.index(f.severity), *sort_key(f)))
    counts = "".join(
        f"<span><span class='sev {s.value}'>{s.value}</span> {sum(1 for f in findings if f.severity is s)}</span>"
        for s in SEVERITIES
    )
    groups = []
    for severity, items in groupby(findings, key=lambda f: f.severity):
        groups.append(
            f"<h2>{_e(severity.value.capitalize())}</h2>"
            + "".join(_finding(f, interactive) for f in items)
        )
    toolbar = ""
    script = ""
    csp = ""
    if interactive:
        rules = sorted({f.rule_id for f in findings})
        sev_opts = "".join(
            f"<option value='{s.value}'>{s.value}</option>"
            for s in SEVERITIES
            if any(f.severity is s for f in findings)
        )
        rule_opts = "".join(f"<option value='{_e(r)}'>{_e(r)}</option>" for r in rules)
        toolbar = (
            "<div class='bar'><input id='q' type='search' placeholder='search'>"
            f"<select id='sev'><option value=''>all severities</option>{sev_opts}</select>"
            f"<select id='rule'><option value=''>all rules</option>{rule_opts}</select>"
            "<label><input id='hide' type='checkbox'> hide judged</label>"
            "<input id='who' type='text' placeholder='reviewer name' size='16'>"
            "<button id='export' type='button'>Export verdicts</button>"
            "<span id='count' class='muted'></span></div>"
        )
        script = f"<script>{SCRIPT}</script>"
        csp = (
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; script-src 'unsafe-inline'\">"
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
        + csp
        + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>vulnfab report</title>"
        f"<style>{CSS}</style></head><body data-target='{_e(result.target)}'><main>"
        f"<h1>vulnfab report</h1><p class='meta'>{_e(result.target)} · stacks: "
        f"{_e(', '.join(result.stacks) or 'none')} · vulnfab {_e(__version__)}</p>"
        f"<div class='counts'>{counts}</div>{toolbar}"
        + ("".join(groups) if groups else "<p>No findings at the current confidence threshold.</p>")
        + "<h2>Coverage &amp; limitations</h2><ul>"
        + notes
        + assumptions
        + "</ul>"
        + (f"<h3>Unresolved constructs</h3><ul>{unresolved}</ul>" if unresolved else "")
        + f"</main>{script}</body></html>\n"
    )
