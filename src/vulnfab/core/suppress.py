"""Suppression: inline ``nosec`` comments, per-file ignores and baselines (WP-2.5)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from vulnfab.core.loader import IgnoreMatcher
from vulnfab.core.models import Finding

NOSEC_RE = re.compile(r"(?:#|//|--)\s*nosec\b(?:\s*:\s*(?P<ids>[a-z0-9][a-z0-9,\s-]*))?", re.I)
BASELINE_VERSION = 1


class BaselineError(Exception):
    pass


def _nosec_ids(line: str) -> set[str] | None:
    """``None`` = no nosec on this line; empty set = suppress every rule."""
    m = NOSEC_RE.search(line)
    if m is None:
        return None
    ids = m.group("ids")
    if not ids:
        return set()
    return {part.strip().lower() for part in ids.split(",") if part.strip()}


def is_nosec(finding: Finding, lines: list[str]) -> bool:
    """A nosec on the first/last line of the finding, or on a comment-only line above it."""
    candidates = [finding.line, finding.end_line]
    for number in candidates:
        if 1 <= number <= len(lines):
            ids = _nosec_ids(lines[number - 1])
            if ids is not None and (not ids or finding.rule_id in ids):
                return True
    above = finding.line - 1
    if 1 <= above <= len(lines):
        text = lines[above - 1].strip()
        if text.startswith(("#", "//", "--")):
            ids = _nosec_ids(text)
            if ids is not None and (not ids or finding.rule_id in ids):
                return True
    return False


class PerFileIgnores:
    def __init__(self, mapping: dict[str, list[str]]) -> None:
        self._entries = [(IgnoreMatcher([glob]), set(rules)) for glob, rules in mapping.items()]

    def ignores(self, path: str, rule_id: str) -> bool:
        return any(
            matcher.is_ignored(path, False) and (not rules or rule_id in rules or "*" in rules)
            for matcher, rules in self._entries
        )


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != BASELINE_VERSION:
        raise BaselineError(f"{path}: unsupported baseline format")
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(f, str) for f in fingerprints):
        raise BaselineError(f"{path}: 'fingerprints' must be a list of strings")
    return set(fingerprints)


def write_baseline(path: Path, findings: Iterable[Finding]) -> int:
    fingerprints = sorted({f.fingerprint for f in findings})
    payload = {"schema_version": BASELINE_VERSION, "fingerprints": fingerprints}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(fingerprints)
