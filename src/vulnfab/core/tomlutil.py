"""TOML parsing with source line numbers for every key (tomllib has none)."""

from __future__ import annotations

import re
import tomllib

from vulnfab.core.models import ConfigDoc

_HEADER = re.compile(r"^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:#.*)?$")
_KEY = re.compile(
    r'^\s*((?:[A-Za-z0-9_-]+|"[^"]*"|\'[^\']*\')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|\'[^\']*\'))*)\s*='
)  # noqa: E501
_PART = re.compile(r'"([^"]*)"|\'([^\']*)\'|([A-Za-z0-9_-]+)')


def _split_path(text: str) -> tuple[str, ...]:
    return tuple(next(g for g in m.groups() if g is not None) for m in _PART.finditer(text))


def parse_toml(path: str, text: str) -> ConfigDoc:
    """Parse ``text``; raises ``tomllib.TOMLDecodeError`` if it is invalid."""
    data = tomllib.loads(text)
    lines: dict[tuple[str, ...], int] = {}
    section: tuple[str, ...] = ()
    in_multiline = False
    for number, raw in enumerate(text.split("\n"), start=1):
        if in_multiline:
            if '"""' in raw or "'''" in raw:
                in_multiline = False
            continue
        header = _HEADER.match(raw)
        if header and not _KEY.match(raw):
            section = _split_path(header.group(1))
            lines.setdefault(section, number)
            continue
        key = _KEY.match(raw)
        if key:
            lines[(*section, *_split_path(key.group(1)))] = number
            rest = raw[key.end() :]
            if rest.count('"""') % 2 == 1 or rest.count("'''") % 2 == 1:
                in_multiline = True
    return ConfigDoc(path=path, data=data, lines=lines)
