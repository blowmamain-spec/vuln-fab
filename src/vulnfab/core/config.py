"""Project configuration file ``.vulnfab.yml`` (WP-2.5)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from vulnfab.core.models import Confidence, Severity

CONFIG_FILE = ".vulnfab.yml"


class ConfigError(Exception):
    pass


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disable_rules: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    min_confidence: Confidence | None = None
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    per_file_ignores: dict[str, list[str]] = Field(default_factory=dict)
    max_file_kb: int | None = Field(default=None, ge=1)
    file_timeout: float | None = Field(default=None, gt=0)

    @field_validator("exclude", "disable_rules")
    @classmethod
    def _no_blank(cls, v: list[str]) -> list[str]:
        if any(not item.strip() for item in v):
            raise ValueError("entries must not be blank")
        return v


def load_config(root: Path) -> ScanConfig:
    path = root / CONFIG_FILE
    if not path.is_file():
        return ScanConfig()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    try:
        return ScanConfig.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"{path}: {details}") from exc
