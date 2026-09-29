"""Supabase / PostgreSQL plugin: migrations -> final-state schema model, config.toml, seed."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from vulnfab.core.models import (
    Bucket,
    Confidence,
    ConfigDoc,
    DataAccess,
    DispatchHint,
    Entrypoint,
    ParsedFile,
    ParsedUnit,
    SchemaModel,
    SourceFile,
    TemplateUnit,
    Unresolved,
)
from vulnfab.core.tomlutil import parse_toml
from vulnfab.plugins.base import RepoView
from vulnfab.plugins.supabase.schema import SchemaBuilder

_CONFIG_RE = re.compile(r"(?:^|.*/)supabase/config\.toml$")
_MIGRATION_RE = re.compile(r"(?:^|.*/)supabase/migrations/[^/]+\.sql$")
_OTHER_RE = re.compile(r"(?:^|.*/)supabase/(?:seed[^/]*\.sql|functions/.+)$")
DEFAULT_EXPOSED_SCHEMAS = ("public", "graphql_public")


def project_roots(paths: Iterable[str]) -> list[str]:
    """Directories that contain a ``supabase/`` project (config.toml or migrations)."""
    roots: set[str] = set()
    for p in paths:
        if _CONFIG_RE.match(p) or _MIGRATION_RE.match(p) or _OTHER_RE.match(p):
            parts = PurePosixPath(p).parts
            idx = len(parts) - 1 - list(reversed(parts)).index("supabase")
            roots.add("/".join(parts[:idx]))
    return sorted(roots)


def exposed_schemas(model: SchemaModel) -> tuple[str, ...]:
    """Schemas exposed through PostgREST (config ``[api] schemas``, default public)."""
    for doc in model.configs.values():
        schemas = doc.data.get("api", {}).get("schemas")
        if isinstance(schemas, list) and schemas:
            return tuple(str(s) for s in schemas)
    return DEFAULT_EXPOSED_SCHEMAS


class SupabasePlugin:
    name = "supabase"
    languages = ["sql", "toml"]

    def detect(self, repo: RepoView) -> Confidence:
        paths = getattr(repo, "paths", None)
        if paths is None:
            return Confidence.LOW
        return Confidence.HIGH if project_roots(paths) else Confidence.LOW

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        unit = ParsedUnit()
        for sf in files:
            unit.files[sf.path] = ParsedFile(path=sf.path, language=sf.language, tree=None)
        return unit

    def extract_schema(self, repo: RepoView) -> SchemaModel | None:
        paths = getattr(repo, "paths", None) or []
        roots = project_roots(paths)
        if not roots:
            return None
        builder = SchemaBuilder()
        model = builder.model
        for root in roots:
            prefix = f"{root}/" if root else ""
            mig_dir = f"{prefix}supabase/migrations/"
            migrations = sorted(
                p
                for p in paths
                if p.startswith(mig_dir) and p.endswith(".sql") and "/" not in p[len(mig_dir) :]
            )
            for path in migrations:
                builder.apply_file(path, repo.read_text(path))
            config_path = f"{prefix}supabase/config.toml"
            if config_path in paths:
                self._load_config(model, repo, config_path)
        if len(roots) > 1:
            model.assumptions.append(
                f"{len(roots)} Supabase projects found ({', '.join(r or '.' for r in roots)}); "
                "their schemas are merged into one model."
            )
        model.assumptions.append(
            "Schema derived from migrations only; changes made in the Supabase dashboard "
            "are not visible."
        )
        return model

    @staticmethod
    def _load_config(model: SchemaModel, repo: RepoView, path: str) -> None:
        try:
            doc: ConfigDoc = parse_toml(path, repo.read_text(path))
        except tomllib.TOMLDecodeError as exc:
            model.unresolved.append(Unresolved("config_parse_error", path, 1, str(exc)))
            return
        model.configs[path] = doc
        buckets = doc.data.get("storage", {}).get("buckets", {})
        if isinstance(buckets, dict):
            for name, cfg in buckets.items():
                if isinstance(cfg, dict):
                    line = doc.lines.get(("storage", "buckets", name), 1)
                    model.buckets[name] = Bucket(
                        name, bool(cfg.get("public", False)), path, line, line
                    )

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        return []

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]:
        return []

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]:
        return []

    def templates(self, repo: RepoView) -> list[TemplateUnit]:
        return []

    def rule_packs(self) -> list[Path]:
        return [Path(__file__).resolve().parents[2] / "rules" / "supabase"]

    def attach_drift(self, model: SchemaModel, name: str, dump_sql: str) -> None:
        """Attach a ``pg_dump --schema-only`` of the live database for drift detection."""
        builder = SchemaBuilder(baseline=False)
        builder.apply_file(name, dump_sql)
        model.drift_source = builder.model
        model.assumptions[:] = [a for a in model.assumptions if "migrations only" not in a]
        model.assumptions.append(f"Schema drift checked against database dump {name}.")

    # Used by the rule test harness: where a test file must live inside a fixture repository.
    def fixture_path(self, filename: str) -> str | None:
        if filename.endswith(".toml"):
            return "supabase/config.toml"
        if filename.startswith("seed") and filename.endswith(".sql"):
            return f"supabase/{filename}"
        if filename.endswith(".sql"):
            return f"supabase/migrations/20240101000000_{filename}"
        return None
