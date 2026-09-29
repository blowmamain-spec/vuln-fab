"""Built-in language-level plugin: parses every tree-sitter language for generic rules.

It carries no framework knowledge; stack plugins (supabase, typescript, django, ...) add that.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from vulnfab.core.models import (
    Confidence,
    DataAccess,
    DispatchHint,
    Entrypoint,
    ParsedUnit,
    SchemaModel,
    SkippedFile,
    SourceFile,
    TemplateUnit,
)
from vulnfab.core.parsing import PARSEABLE_LANGUAGES, ParseFailure, parse_file
from vulnfab.plugins.base import RepoView


class GenericPlugin:
    name = "generic"
    languages = sorted(PARSEABLE_LANGUAGES)

    def detect(self, repo: RepoView) -> Confidence:
        return Confidence.HIGH

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        unit = ParsedUnit()
        for sf in files:
            if sf.language not in PARSEABLE_LANGUAGES:
                continue
            try:
                unit.files[sf.path] = parse_file(sf)
            except ParseFailure as exc:
                unit.skipped.append(SkippedFile(sf.path, exc.reason, exc.detail))
        return unit

    def extract_schema(self, repo: RepoView) -> SchemaModel | None:
        return None

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        return []

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]:
        return []

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]:
        return []

    def templates(self, repo: RepoView) -> list[TemplateUnit]:
        return []

    def rule_packs(self) -> list[Path]:
        return []
