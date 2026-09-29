"""Scan orchestration: load -> detect -> parse -> rules -> score -> result."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from vulnfab.core import trivial
from vulnfab.core.fingerprint import FingerprintAllocator
from vulnfab.core.loader import DEFAULT_MAX_FILE_BYTES, Repo
from vulnfab.core.models import Confidence, Finding, ParsedUnit, SkippedFile
from vulnfab.core.parsing import TimeoutExceeded
from vulnfab.core.report import Coverage, ScanResult
from vulnfab.plugins import registry


@dataclass
class ScanOptions:
    stacks: list[str] | None = None
    min_confidence: Confidence = Confidence.MEDIUM
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    file_timeout: float = 10.0


def scan(path: Path, options: ScanOptions | None = None) -> ScanResult:
    options = options or ScanOptions()
    repo = Repo(path, max_file_bytes=options.max_file_bytes)
    plugins = registry.discover()
    selected = registry.select(plugins, repo, options.stacks)
    loaded = repo.load()

    coverage = Coverage(
        files_skipped=list(loaded.skipped),
        files_ignored=loaded.ignored_count,
        files_unsupported=loaded.unsupported_count,
    )
    scanned: set[str] = set()
    raw: list[tuple[Finding, str]] = []

    for sel in selected:
        plugin = sel.plugin
        files = [f for f in loaded.files if f.language in plugin.languages]
        unit: ParsedUnit = plugin.parse(files)
        coverage.files_skipped.extend(unit.skipped)
        coverage.unresolved.extend(unit.unresolved)
        for pf in unit.files.values():
            scanned.add(pf.path)
            if pf.has_syntax_errors:
                coverage.syntax_errors.append(pf.path)
        if plugin.name == "generic":
            try:
                raw.extend(trivial.run(unit, options.file_timeout))
            except TimeoutExceeded:
                coverage.files_skipped.append(
                    SkippedFile("(generic rules)", "timeout", f"exceeded {options.file_timeout:g}s")
                )

    coverage.files_scanned = len(scanned)
    coverage.syntax_errors.sort()
    coverage.files_skipped.sort(key=lambda s: (s.file, s.reason))

    allocator = FingerprintAllocator()
    findings: list[Finding] = []
    for finding, symbol in sorted(raw, key=lambda item: (item[0].file, item[0].line)):
        fingerprint = allocator.allocate(finding.rule_id, finding.file, finding.snippet, symbol)
        findings.append(replace(finding, fingerprint=fingerprint))

    visible = [f for f in findings if f.confidence.rank >= options.min_confidence.rank]
    coverage.hidden_low_confidence = len(findings) - len(visible)
    return ScanResult(
        target=str(path),
        stacks=[s.plugin.name for s in selected],
        findings=visible,
        coverage=coverage,
    )
