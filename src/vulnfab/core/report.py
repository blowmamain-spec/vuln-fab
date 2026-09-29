"""Scan result model and its JSON form (docs/spec.md section 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vulnfab import __version__
from vulnfab.core.models import Finding, SkippedFile, Unresolved, to_jsonable

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AdapterStatus:
    name: str
    status: str  # ok | missing | error
    detail: str = ""


@dataclass
class Coverage:
    files_scanned: int = 0
    files_skipped: list[SkippedFile] = field(default_factory=list)
    files_ignored: int = 0
    files_unsupported: int = 0
    syntax_errors: list[str] = field(default_factory=list)
    unresolved: list[Unresolved] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    adapters: list[AdapterStatus] = field(default_factory=list)
    hidden_low_confidence: int = 0


@dataclass
class ScanResult:
    target: str
    stacks: list[str]
    findings: list[Finding]
    coverage: Coverage


def sort_key(f: Finding) -> tuple[str, int, str]:
    return (f.file, f.line, f.rule_id)


def to_json_dict(result: ScanResult) -> dict[str, Any]:
    findings = sorted(result.findings, key=sort_key)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "vulnfab", "version": __version__},
        "target": {"path": result.target, "stacks": result.stacks},
        "findings": to_jsonable(findings),
        "coverage": to_jsonable(result.coverage),
    }
