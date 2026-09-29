"""A minimal third-party plugin exercises the frozen contract through public APIs only."""
# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import (
    AuthInfo,
    Confidence,
    Entrypoint,
    ParsedUnit,
    SchemaModel,
    SourceFile,
)
from vulnfab.plugins import base, registry

RULES = """
rules:
  - id: demo-eval-call
    stack: demo
    languages: [python]
    severity: high
    confidence: medium
    message: "eval call"
    pattern: "eval($X)"
    where: [{metavariable: X, kind: not_literal}]
    tests: {vulnerable: [v.py], safe: [s.py]}
  - id: demo-table
    kind: schema
    stack: demo
    severity: medium
    confidence: medium
    message: "table without owner"
    check: "vulnfab.plugins.base:CONTRACT_VERSION"
    tests: {vulnerable: [v.py], safe: [s.py]}
"""


class DemoPlugin:
    name = "demo"
    languages = ["python"]

    def __init__(self, pack: Path) -> None:
        self.pack = pack

    def detect(self, repo: base.RepoView) -> Confidence:
        return Confidence.HIGH if repo.exists("demo.marker") else Confidence.LOW

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        from vulnfab.core.parsing import parse_file_cached

        unit = ParsedUnit()
        for sf in files:
            if sf.language == "python":
                unit.files[sf.path] = parse_file_cached(sf)
        return unit

    def extract_schema(self, repo: base.RepoView) -> SchemaModel | None:
        return None

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        return [Entrypoint("demo", f, 1, "handler", auth=AuthInfo(False)) for f in unit.files]

    def data_access(self, unit: ParsedUnit) -> list:  # type: ignore[type-arg]
        return []

    def dispatch_hints(self, unit: ParsedUnit) -> list:  # type: ignore[type-arg]
        return []

    def templates(self, repo: base.RepoView) -> list:  # type: ignore[type-arg]
        return []

    def rule_packs(self) -> list[Path]:
        return [self.pack]


def test_contract_version_is_frozen_and_documented() -> None:
    assert base.CONTRACT_VERSION == "1.0"
    text = (
        Path(__file__).resolve().parents[2] / "docs/decisions/plugin-contract-freeze.md"
    ).read_text()
    assert "Plugin contract 1.0" in text


def test_builtin_plugins_implement_the_protocol() -> None:
    names = {p.name for p in registry.discover()}
    assert {"generic", "django", "supabase", "typescript"} <= names
    for plugin in registry.discover():
        assert isinstance(plugin, base.StackPlugin)


def test_third_party_plugin_runs_without_core_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "rules.yml").write_text(
        RULES.replace(
            'check: "vulnfab.plugins.base:CONTRACT_VERSION"',
            'check: "vulnfab.plugins.django.checks:debug_true"',
        )
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "demo.marker").write_text("x")
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\n")
    demo = DemoPlugin(pack)
    real = registry.discover
    monkeypatch.setattr(registry, "discover", lambda: [*real(), demo])
    result = scan(repo, ScanOptions(min_confidence=Confidence.LOW))
    assert "demo" in result.stacks
    assert any(f.rule_id == "demo-eval-call" and f.file == "app.py" for f in result.findings)


def test_plugin_without_marker_is_not_activated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "rules.yml").write_text("rules: []\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    real = registry.discover
    monkeypatch.setattr(registry, "discover", lambda: [*real(), DemoPlugin(pack)])
    assert "demo" not in scan(repo).stacks
