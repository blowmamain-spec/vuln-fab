"""Spike S3: tokenizers for Django templates and Blade (throwaway; production in WP-6.3/7.3)."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Tok:
    kind: str  # output | output_raw | tag | php_block | comment
    text: str
    line: int


DJANGO_RE = re.compile(r"\{#.*?#\}|\{\{(.*?)\}\}|\{%(.*?)%\}", re.DOTALL)
BLADE_RE = re.compile(
    r"\{\{--.*?--\}\}|@\{\{.*?\}\}|\{!!(?P<raw>.*?)!!\}|\{\{(?P<esc>.*?)\}\}"
    r"|@php\b(?P<php>.*?)@endphp|@verbatim.*?@endverbatim",
    re.DOTALL,
)


def _line(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def django_tokens(src: str) -> list[Tok]:
    out = []
    for m in DJANGO_RE.finditer(src):
        s = m.group()
        if s.startswith("{#"):
            out.append(Tok("comment", s, _line(src, m.start())))
        elif s.startswith("{{"):
            out.append(Tok("output", m.group(1).strip(), _line(src, m.start())))
        else:
            out.append(Tok("tag", m.group(2).strip(), _line(src, m.start())))
    return out


def django_unsafe(src: str) -> list[int]:
    """Lines where output bypasses autoescape: |safe, |escape-free filters, or inside autoescape off."""
    lines, off_depth = [], 0
    for t in django_tokens(src):
        if t.kind == "tag":
            if re.fullmatch(r"autoescape\s+off", t.text):
                off_depth += 1
            elif t.text == "endautoescape" and off_depth:
                off_depth -= 1
        elif t.kind == "output" and (re.search(r"\|\s*safe\b", t.text) or off_depth):
            lines.append(t.line)
    return lines


def blade_unsafe(src: str) -> list[int]:
    lines = []
    for m in BLADE_RE.finditer(src):
        if m.group("raw") is not None:
            lines.append(_line(src, m.start()))
    return lines


CASES = [
    ("django", "<p>{{ name }}</p>", []),
    ("django", "<p>{{ bio|safe }}</p>", [1]),
    ("django", "<p>{{ bio | safe }}</p>", [1]),
    ("django", "{% autoescape off %}\n{{ x }}\n{% endautoescape %}\n{{ y }}", [2]),
    ("django", "{# {{ x|safe }} #}", []),
    ("django", "{{ x|default:'a'|safe }}", [1]),
    ("django", "{{ x|safeish }}", []),
    ("django", "a\n\n{{ y|safe }}", [3]),
    ("blade", "<p>{{ $name }}</p>", []),
    ("blade", "<p>{!! $bio !!}</p>", [1]),
    ("blade", "{{-- {!! $x !!} --}}", []),
    ("blade", "@verbatim {!! $x !!} @endverbatim", []),
    ("blade", "a\n{!! $a !!}\n{{ $b }}\n{!! $c !!}", [2, 4]),
    ("blade", "@{{ literal }}", []),
    ("blade", "@php echo '{!! x !!}'; @endphp", []),
]

if __name__ == "__main__":
    ok = 0
    for kind, src, want in CASES:
        got = django_unsafe(src) if kind == "django" else blade_unsafe(src)
        good = got == want
        ok += good
        print("PASS" if good else "FAIL", kind, repr(src), got, want)
    print(f"{ok}/{len(CASES)}")
