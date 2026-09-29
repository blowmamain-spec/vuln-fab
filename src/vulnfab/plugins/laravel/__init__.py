"""Laravel plugin: migrations + Eloquent models -> schema, routes -> entrypoints, Blade rules."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from vulnfab.core.models import (
    Confidence,
    DataAccess,
    DispatchHint,
    Entrypoint,
    Finding,
    ParsedUnit,
    SchemaModel,
    SkippedFile,
    SourceFile,
    TemplateUnit,
    Unresolved,
)
from vulnfab.core.parsing import ParseFailure, parse_file_cached
from vulnfab.plugins.base import RepoView
from vulnfab.plugins.laravel import eloquent, routes
from vulnfab.plugins.laravel.migrations import SCHEMA, MigrationBuilder

_MIGRATION_RE = re.compile(r"(?:^|.*/)database/migrations/[^/]+\.php$")
_MODEL_RE = re.compile(r"(?:^|.*/)app/(?:Models/)?[^/]+\.php$|(?:^|.*/)app/Models/.+\.php$")
_ROUTES_RE = re.compile(r"(?:^|.*/)routes/[^/]+\.php$")
_SKIP = ("/vendor/", "/node_modules/", "/storage/")
_PHP_LANGS = ("php", "blade")


def _skip(path: str) -> bool:
    return any(marker in f"/{path}" for marker in _SKIP)


class LaravelPlugin:
    name = "laravel"
    languages = ["php"]

    def detect(self, repo: RepoView) -> Confidence:
        paths = [p for p in (getattr(repo, "paths", None) or []) if not _skip(p)]
        names = {p.rsplit("/", 1)[-1] for p in paths}
        if "artisan" in names:
            return Confidence.HIGH
        for p in paths:
            if p.rsplit("/", 1)[-1] == "composer.json":
                try:
                    data = json.loads(repo.read_text(p))
                except (OSError, KeyError, ValueError):
                    continue
                deps = {**data.get("require", {}), **data.get("require-dev", {})}
                if "laravel/framework" in deps:
                    return Confidence.HIGH
                if any(d.startswith("illuminate/") for d in deps):
                    return Confidence.MEDIUM
        return Confidence.LOW

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        unit = ParsedUnit()
        for sf in files:
            if sf.language != "php":
                continue
            try:
                unit.files[sf.path] = parse_file_cached(sf)
            except ParseFailure as exc:
                unit.skipped.append(SkippedFile(sf.path, exc.reason, exc.detail))
        return unit

    # --- schema ----------------------------------------------------------------------------

    def extract_schema(self, repo: RepoView) -> SchemaModel | None:
        paths = [p for p in (getattr(repo, "paths", None) or []) if not _skip(p)]
        migrations = sorted(p for p in paths if _MIGRATION_RE.match(p))
        models = sorted(p for p in paths if p.endswith(".php") and _MODEL_RE.match(p))
        if not migrations and not models:
            return None
        builder = MigrationBuilder()
        for path in migrations:
            builder.apply_file(path, repo.read_text(path))
        model = builder.model
        for path in models:
            try:
                text = repo.read_text(path)
            except (OSError, KeyError):
                continue
            if "extends" not in text:
                continue
            for em in eloquent.read_models(path, text):
                table = model.tables.get(f"{SCHEMA}.{em.table}")
                if table is None:
                    model.unresolved.append(
                        Unresolved(
                            "model_without_migration",
                            path,
                            em.line,
                            f"{em.name}: no migration creates table {em.table!r}",
                        )
                    )
                    continue
                table.extras.update(
                    model=em.name,
                    model_file=em.file,
                    model_line=em.line,
                    fillable=em.fillable,
                    guarded=em.guarded,
                    guarded_line=em.guarded_line,
                    hidden=em.hidden,
                    relations=em.relations,
                )
        model.assumptions.append(
            "Laravel schema is read from database/migrations (up() methods only); changes made "
            "outside migrations are not visible."
        )
        return model

    # --- contract stubs (filled in as the plugin grows) ------------------------------------------

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        route_files = {
            p: pf
            for p, pf in unit.files.items()
            if _ROUTES_RE.match(p) and not p.endswith(("console.php", "channels.php"))
        }
        if not route_files:
            return []
        collector = routes.RouteCollector(unit.unresolved)
        imports_by_file: dict[str, dict[str, str]] = {}
        for path, pf in sorted(route_files.items()):
            collector.collect(path, pf)
            imports_by_file[path] = collector.imports
        controllers = routes.index_controllers(unit.files)
        sources = {p: pf.source for p, pf in route_files.items()}
        return routes.to_entrypoints(
            collector.routes,
            controllers,
            imports_by_file,
            sources,
            routes.csrf_except(unit.files),
            unit.unresolved,
        )

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]:
        return []

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]:
        return []

    def templates(self, repo: RepoView) -> list[TemplateUnit]:
        return []

    def rule_packs(self) -> list[Path]:
        return [Path(__file__).resolve().parents[2] / "rules" / "laravel"]

    def refine(
        self, raw: list[tuple[Finding, str]], model: SchemaModel
    ) -> list[tuple[Finding, str]]:
        return raw

    def fixture_path(self, filename: str) -> str | None:
        if filename.startswith("migration"):
            return "database/migrations/2024_01_01_000000_create_test.php"
        if "routes" in filename:
            return "routes/web.php"
        if filename.startswith("model"):
            return "app/Models/Model.php"
        return None
