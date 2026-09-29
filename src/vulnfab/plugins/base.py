"""The stack plugin contract (docs/spec.md section 6).

Plugins must not import other plugins; they communicate only through the shared IR.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, runtime_checkable

from vulnfab.core.models import (
    Confidence,
    DataAccess,
    DispatchHint,
    Entrypoint,
    ParsedUnit,
    SchemaModel,
    SourceFile,
    TemplateUnit,
)

CONTRACT_VERSION = "1.0"  # frozen after the third plugin (Django); see docs/decisions/


class RepoView(Protocol):
    """Read-only view of the scanned repository."""

    root: Path

    def exists(self, rel_path: str) -> bool: ...

    def read_text(self, rel_path: str) -> str: ...

    def glob(self, pattern: str) -> list[str]: ...


@runtime_checkable
class StackPlugin(Protocol):
    name: str
    languages: list[str]

    def detect(self, repo: RepoView) -> Confidence: ...

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit: ...

    def extract_schema(self, repo: RepoView) -> SchemaModel | None: ...

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]: ...

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]: ...

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]: ...

    def templates(self, repo: RepoView) -> list[TemplateUnit]: ...

    def rule_packs(self) -> list[Path]: ...


# Optional hooks (looked up with getattr; a plugin that does not need them simply omits them):
#   fixture_path(filename) -> str | None      where a rule-test file lives inside a fixture repo
#   attach_drift(model, name, dump) -> None   compare the schema with a live database dump
#   refine(raw, model) -> raw                 adjust findings using the plugin's schema model
