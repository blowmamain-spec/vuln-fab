"""Project-specific taint sanitizers and validators from .vulnfab.yml."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnfab.core.config import ConfigError, load_config
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence

CODE = """<?php
function a() {
    $p = $_GET['file'];
    echo file_get_contents(clean_path($p));
    if (!path_ok($p)) { return; }
    echo file_get_contents($p);
}
"""


def repo(tmp_path: Path, config: str = "") -> Path:
    (tmp_path / "a.php").write_text(CODE)
    if config:
        (tmp_path / ".vulnfab.yml").write_text(config)
    return tmp_path


def lines(tmp_path: Path) -> set[int]:
    result = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW))
    return {f.line for f in result.findings if f.rule_id == "tphp-pathtrav"}


def test_default_reports_both(tmp_path: Path) -> None:
    assert lines(repo(tmp_path)) == {4, 6}


def test_custom_sanitizer_and_validator(tmp_path: Path) -> None:
    cfg = "taint:\n  sanitizers: ['call clean_path']\n  validators: ['call path_ok']\n"
    assert lines(repo(tmp_path, cfg)) == set()


def test_bad_entry_is_a_config_error(tmp_path: Path) -> None:
    (tmp_path / ".vulnfab.yml").write_text("taint:\n  sanitizers: ['nonsense']\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)
