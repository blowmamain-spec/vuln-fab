"""TypeScript/JavaScript plugin: supabase-js data access facts and frontend/API-route rules."""

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
from vulnfab.core.parsing import ParseFailure, parse_file_cached
from vulnfab.plugins.base import RepoView
from vulnfab.plugins.typescript import dataaccess

TS_LANGUAGES = ("typescript", "tsx", "javascript")


class TypeScriptPlugin:
    name = "typescript"
    languages = [*TS_LANGUAGES, "env", "toml"]

    def detect(self, repo: RepoView) -> Confidence:
        paths = getattr(repo, "paths", None) or []
        markers = ("package.json", "tsconfig.json", "deno.json", "deno.jsonc")
        if any(p.rsplit("/", 1)[-1] in markers for p in paths):
            return Confidence.HIGH
        if any(p.endswith((".ts", ".tsx")) for p in paths):
            return Confidence.MEDIUM
        return Confidence.LOW

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        unit = ParsedUnit()
        for sf in files:
            if sf.language not in TS_LANGUAGES:
                continue
            try:
                unit.files[sf.path] = parse_file_cached(sf)
            except ParseFailure as exc:
                unit.skipped.append(SkippedFile(sf.path, exc.reason, exc.detail))
        return unit

    def extract_schema(self, repo: RepoView) -> SchemaModel | None:
        return None

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        return []

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]:
        accesses, unresolved = dataaccess.extract(unit.files)
        unit.unresolved.extend(unresolved)
        return accesses

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]:
        return []

    def templates(self, repo: RepoView) -> list[TemplateUnit]:
        return []

    def rule_packs(self) -> list[Path]:
        return [Path(__file__).resolve().parents[2] / "rules" / "typescript"]
