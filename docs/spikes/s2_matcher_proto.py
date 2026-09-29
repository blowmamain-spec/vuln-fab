"""Spike S2: snippet-pattern matcher with metavariables on tree-sitter (Python, TS, PHP).

Throwaway prototype; the production matcher is WP-2.3. Run: uv run python docs/spikes/s2_matcher_proto.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import tree_sitter_php as tsphp
import tree_sitter_python as tspy
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

LANGS = {
    "python": Language(tspy.language()),
    "typescript": Language(tsts.language_typescript()),
    "php": Language(tsphp.language_php()),
}
MV = re.compile(r"\$([A-Z_][A-Z0-9_]*)")
ELL = "__ELLIPSIS__"


def parse(lang: str, src: str):
    p = Parser(LANGS[lang])
    if lang == "php" and not src.lstrip().startswith("<?php"):
        src = "<?php " + src
    return p.parse(src.encode()), src.encode()


def prep_pattern(lang: str, pat: str) -> str:
    pat = pat.replace("...", ELL)
    pat = MV.sub(lambda m: ("$" if lang == "php" else "") + "__MV_" + m.group(1), pat)
    if lang == "php" and not pat.endswith((";", "}")):
        pat += ";"
    return pat


def sig(n: Node) -> list[Node]:
    return [c for c in n.children if c.type != "comment"]


def unwrap(n: Node) -> Node:
    """Descend from the file root to the single expression the pattern denotes."""
    while True:
        kids = [c for c in sig(n) if c.type not in ("<?php", "php_tag", ";", "text")]
        if n.type in ("module", "program", "expression_statement", "php_tag") and len(kids) >= 1:
            n = kids[0] if n.type != "program" else next(k for k in kids if k.type != "php_tag")
            continue
        return n


@dataclass
class Matcher:
    pat_src: bytes
    tgt_src: bytes

    def text(self, n: Node, pat: bool) -> str:
        return (self.pat_src if pat else self.tgt_src)[n.start_byte : n.end_byte].decode()

    def mv(self, n: Node) -> str | None:
        t = self.text(n, True)
        m = re.fullmatch(r"\$?__MV_([A-Z0-9_]+)", t)
        return m.group(1) if m else None

    def match(self, p: Node, t: Node, env: dict[str, str]) -> bool:
        name = self.mv(p)
        if name is not None and p.child_count <= 2:
            val = self.text(t, False)
            if env.setdefault(name, val) != val:
                return False
            return True
        if p.type != t.type:
            return False
        pk, tk = sig(p), sig(t)
        if not pk:
            return self.text(p, True) == self.text(t, False)
        return self.match_seq(pk, tk, env)

    def is_ell(self, n: Node) -> bool:
        return self.text(n, True) == ELL or (n.type == "argument" and self.text(n, True) == ELL)

    def match_seq(self, pk: list[Node], tk: list[Node], env: dict[str, str]) -> bool:
        if not pk:
            return not tk
        head = pk[0]
        if self.is_ell(head) or (head.child_count == 1 and self.is_ell(head.children[0])):
            for skip in range(len(tk) + 1):
                trial = dict(env)
                if self.match_seq(pk[1:], tk[skip:], trial):
                    env.update(trial)
                    return True
            return False
        if not tk:
            return False
        trial = dict(env)
        if self.match(head, tk[0], trial) and self.match_seq(pk[1:], tk[1:], trial):
            env.update(trial)
            return True
        return False


def find(lang: str, pattern: str, code: str) -> list[dict[str, str]]:
    ptree, psrc = parse(lang, prep_pattern(lang, pattern))
    ttree, tsrc = parse(lang, code)
    root = unwrap(ptree.root_node)
    m = Matcher(psrc, tsrc)
    hits: list[dict[str, str]] = []

    def walk(n: Node) -> None:
        if n.type == root.type:
            env: dict[str, str] = {}
            if m.match(root, n, env):
                hits.append(env)
        for c in n.children:
            walk(c)

    walk(ttree.root_node)
    return hits


# (language, pattern, code, expected number of matches)
CASES = [
    ("python", "eval($X)", "eval(user)", 1),
    ("python", "eval($X)", "evaluate(user)", 0),
    ("python", "eval($X)", "def f():\n    return eval(a + b)", 1),
    ("python", "$M.objects.raw($Q)", "User.objects.raw(q)", 1),
    ("python", "$M.objects.raw($Q)", "User.objects.filter(q)", 0),
    ("python", "subprocess.run(..., shell=True)", "subprocess.run(cmd, shell=True)", 1),
    ("python", "subprocess.run(..., shell=True)", "subprocess.run(cmd, shell=False)", 0),
    ("python", "subprocess.run(..., shell=True)", "subprocess.run(a, b, cwd=x, shell=True)", 1),
    ("python", "$X == $X", "a == a", 1),
    ("python", "$X == $X", "a == b", 0),
    ("typescript", "eval($X)", "eval(input)", 1),
    ("typescript", "eval($X)", "myeval(input)", 0),
    ("typescript", "$EL.innerHTML = $X", "el.innerHTML = user", 1),
    ("typescript", "$EL.innerHTML = $X", "el.textContent = user", 0),
    ("typescript", "child_process.exec($X)", "child_process.exec(cmd)", 1),
    ("typescript", "supabase.from($T).select(...)", "supabase.from('a').select('*').eq('id', 1)", 1),
    ("typescript", "supabase.from($T).select(...)", "supabase.from('a').insert({})", 0),
    ("typescript", "new Function($X)", "const f = new Function(code)", 1),
    ("typescript", "$X.or(...)", "q.or(`a.eq.${v}`)", 1),
    ("typescript", "fetch($U, ...)", "fetch(url, {method: 'POST'})", 1),
    ("php", "eval($X)", "eval($code);", 1),
    ("php", "unserialize($X)", "$o = unserialize($_GET['d']);", 1),
    ("php", "unserialize($X)", "$o = json_decode($d);", 0),
    ("php", "DB::raw($X)", "DB::raw($sql);", 1),
    ("php", "DB::raw($X)", "DB::table($sql);", 0),
    ("php", "$request->input(...)", "$id = $request->input('id');", 1),
    ("php", "$request->input(...)", "$id = $request->query('id');", 0),
    ("php", "exec($X)", "exec($cmd, $out);", 0),
    ("php", "exec($X, ...)", "exec($cmd, $out);", 1),
    ("php", "$DB->whereRaw($X)", "$q->whereRaw($cond);", 1),
]

if __name__ == "__main__":
    ok = 0
    for lang, pat, code, want in CASES:
        got = len(find(lang, pat, code))
        good = (got > 0) == (want > 0)
        ok += good
        print(("PASS" if good else "FAIL"), lang, pat, "|", code.replace("\n", "\\n"), "->", got)
    print(f"{ok}/{len(CASES)}")
