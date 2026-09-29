from pathlib import Path

import pytest

from vulnfab.core.loader import Repo
from vulnfab.core.models import Confidence
from vulnfab.plugins import registry
from vulnfab.plugins.generic import GenericPlugin


class _Stub(GenericPlugin):
    def __init__(self, name: str, confidence: Confidence) -> None:
        self.name = name
        self._confidence = confidence

    def detect(self, repo):  # type: ignore[no-untyped-def]
        return self._confidence


def test_discover_includes_generic() -> None:
    names = [p.name for p in registry.discover()]
    assert "generic" in names


def test_activation_threshold(tmp_path: Path) -> None:
    repo = Repo(tmp_path)
    plugins = [
        GenericPlugin(),
        _Stub("strong", Confidence.HIGH),
        _Stub("medium", Confidence.MEDIUM),
        _Stub("weak", Confidence.LOW),
    ]
    names = [s.plugin.name for s in registry.select(plugins, repo)]
    assert names == ["generic", "strong", "medium"]


def test_forced_stack_restricts_to_forced_plus_generic(tmp_path: Path) -> None:
    repo = Repo(tmp_path)
    plugins = [GenericPlugin(), _Stub("a", Confidence.HIGH), _Stub("b", Confidence.LOW)]
    selected = registry.select(plugins, repo, ["b"])
    assert [(s.plugin.name, s.forced) for s in selected] == [("generic", False), ("b", True)]


def test_unknown_forced_stack_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(registry.UnknownStackError, match="nope"):
        registry.select([GenericPlugin()], Repo(tmp_path), ["nope"])
