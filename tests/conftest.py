"""Shared fixtures: keep the result cache out of the developer's real cache directory."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VULNFAB_CACHE_DIR", str(tmp_path_factory.mktemp("vulnfab-cache")))
