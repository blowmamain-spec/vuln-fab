"""Stable finding fingerprints (docs/spec.md section 3).

The fingerprint deliberately excludes line numbers so that baselines survive code motion.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter

_SEP = "\x1f"

# Strings first so comment markers inside them are preserved; then comments; then whitespace.
_TOKEN_RE = re.compile(
    r"""
    (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)
    |(?P<block>/\*.*?\*/)
    |(?P<line>(?://|(?<![^\s])\#|--(?=\s|$))[^\n]*)
    """,
    re.VERBOSE | re.DOTALL,
)


def normalize_snippet(text: str) -> str:
    """Strip comments and collapse whitespace while preserving string literals."""
    parts: list[str] = []
    pos = 0
    for m in _TOKEN_RE.finditer(text):
        parts.append(_collapse(text[pos : m.start()]))
        if m.lastgroup == "string":
            parts.append(m.group())
        pos = m.end()
    parts.append(_collapse(text[pos:]))
    return " ".join(p for p in parts if p).strip()


def _collapse(chunk: str) -> str:
    return " ".join(chunk.split())


def compute_fingerprint(
    rule_id: str, path: str, snippet: str, symbol: str = "", occurrence: int = 0
) -> str:
    payload = _SEP.join([rule_id, path, normalize_snippet(snippet), symbol, str(occurrence)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


class FingerprintAllocator:
    """Assigns occurrence indexes to repeated (rule, path, snippet, symbol) tuples."""

    def __init__(self) -> None:
        self._seen: Counter[tuple[str, str, str, str]] = Counter()

    def allocate(self, rule_id: str, path: str, snippet: str, symbol: str = "") -> str:
        key = (rule_id, path, normalize_snippet(snippet), symbol)
        occurrence = self._seen[key]
        self._seen[key] += 1
        return compute_fingerprint(rule_id, path, snippet, symbol, occurrence)
