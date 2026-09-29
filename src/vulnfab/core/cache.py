"""On-disk cache of analysis results (WP-10.4).

The key covers everything the analysis depends on: tool code, rule files, every scanned file's
content hash, the repository configuration and the analysis options. If any of it changes, the
key changes, so a cached result is always identical to a fresh scan.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import vulnfab
from vulnfab.core.models import (
    Confidence,
    Finding,
    Severity,
    SkippedFile,
    TraceStep,
    Unresolved,
    to_jsonable,
)
from vulnfab.core.report import AdapterStatus, Coverage

FORMAT_VERSION = 2
KEEP_PER_TARGET = 3


def cache_dir() -> Path:
    explicit = os.environ.get("VULNFAB_CACHE_DIR")
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "vulnfab"


def code_fingerprint() -> str:
    """Hash of the tool's own source and rule files (size + mtime; cheap and sufficient)."""
    root = Path(vulnfab.__file__).resolve().parent
    digest = hashlib.sha256(vulnfab.__version__.encode())
    for path in sorted(root.rglob("*")):
        if path.suffix in {".py", ".yml", ".yaml"} and "__pycache__" not in path.parts:
            stat = path.stat()
            digest.update(f"{path.relative_to(root)}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    return digest.hexdigest()


def file_digest(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rule_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for base in sorted(paths):
        files = [base] if base.is_file() else sorted(base.rglob("*.y*ml")) if base.is_dir() else []
        for f in files:
            digest.update(str(f.name).encode())
            digest.update(f.read_bytes())
    return digest.hexdigest()


def tree_digest(base: Path) -> str:
    """Digest of every file under ``base`` (or of the single file)."""
    digest = hashlib.sha256()
    files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
    for f in files:
        digest.update(f.name.encode())
        digest.update(f.read_bytes())
    return digest.hexdigest()


def scan_key(parts: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


def _target_dir(target: Path) -> Path:
    return cache_dir() / hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]


def load(target: Path, key: str) -> dict[str, Any] | None:
    path = _target_dir(target) / f"{key}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("format") == FORMAT_VERSION else None


def store(target: Path, key: str, payload: dict[str, Any]) -> None:
    directory = _target_dir(target)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / f"{key}.json.tmp"
        tmp.write_text(json.dumps({"format": FORMAT_VERSION, **payload}), encoding="utf-8")
        tmp.replace(directory / f"{key}.json")
        entries = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in entries[KEEP_PER_TARGET:]:
            old.unlink(missing_ok=True)
    except OSError:
        pass  # a cache that cannot be written is simply not used


# --- (de)serialisation ---------------------------------------------------------------------------


def findings_to_json(findings: list[Finding]) -> list[Any]:
    return to_jsonable(findings)  # type: ignore[no-any-return]


def findings_from_json(items: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for d in items:
        d = dict(d)
        d["cwe"] = tuple(d.get("cwe", ()))
        d["severity"] = Severity(d["severity"])
        d["confidence"] = Confidence(d["confidence"])
        d["trace"] = tuple(TraceStep(**t) for t in d.get("trace", ()))
        out.append(Finding(**d))
    return out


def coverage_to_json(coverage: Coverage) -> dict[str, Any]:
    return to_jsonable(coverage)  # type: ignore[no-any-return]


def coverage_from_json(d: dict[str, Any]) -> Coverage:
    d = dict(d)
    d["files_skipped"] = [SkippedFile(**s) for s in d.get("files_skipped", [])]
    d["unresolved"] = [Unresolved(**u) for u in d.get("unresolved", [])]
    d["adapters"] = [AdapterStatus(**a) for a in d.get("adapters", [])]
    return Coverage(**d)
