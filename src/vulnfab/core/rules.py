"""Rule schema, YAML loader and validator (docs/spec.md section 7)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from vulnfab.core.models import Confidence, Severity, Tier
from vulnfab.core.safeexpr import UnsafeExpression, compile_expression

RULE_ID_RE = re.compile(r"^[a-z]+-[a-z0-9]+(?:-[a-z0-9]+)*$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
METAVAR_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

KNOWN_LANGUAGES = frozenset(
    {"python", "javascript", "typescript", "tsx", "php", "sql", "toml", "env", "blade", "django"}
)
SCHEMA_CONDITION_NAMES = frozenset({"table", "policy", "function", "view", "bucket", "config"})

WhereKind = Literal[
    "literal", "not_literal", "identifier", "fstring_or_concat", "not_fstring_or_concat",
    "unsafe_interpolation", "regex", "not_regex",
]  # fmt: skip


def _as_list(value: Any) -> Any:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RuleTests(_Strict):
    vulnerable: list[str] = Field(default_factory=list)
    safe: list[str] = Field(default_factory=list)


class WhereClause(_Strict):
    metavariable: str
    kind: WhereKind
    regex: str | None = None

    @field_validator("metavariable")
    @classmethod
    def _metavar(cls, v: str) -> str:
        v = v.lstrip("$")
        if not METAVAR_RE.match(v):
            raise ValueError("metavariable must look like X or MY_VAR (upper case)")
        return v

    @model_validator(mode="after")
    def _regex_needed(self) -> WhereClause:
        needs = self.kind in {"regex", "not_regex"}
        if needs and not self.regex:
            raise ValueError(f"kind {self.kind!r} requires 'regex'")
        if not needs and self.regex:
            raise ValueError(f"'regex' is only valid with kind regex/not_regex, not {self.kind!r}")
        if self.regex:
            try:
                re.compile(self.regex)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
        return self


class _RuleBase(_Strict):
    id: str
    stack: str
    severity: Severity
    confidence: Confidence
    cwe: list[str] = Field(default_factory=list)
    message: str
    title: str | None = None
    owasp: str | None = None
    tier: Tier | None = None
    fix: str | None = None
    supersedes: list[str] = Field(default_factory=list)
    tests: RuleTests
    enabled: bool = True

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not RULE_ID_RE.match(v):
            raise ValueError("id must look like 'py-eval' (lowercase, dash separated)")
        return v

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v: Any) -> Any:
        for item in _as_list(v):
            if not isinstance(item, str) or not CWE_RE.match(item):
                raise ValueError(f"bad CWE {item!r} (expected CWE-<number>)")
        return _as_list(v)

    @field_validator("message")
    @classmethod
    def _message(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be empty")
        return v

    @model_validator(mode="after")
    def _needs_tests(self) -> _RuleBase:
        if not self.tests.vulnerable or not self.tests.safe:
            raise ValueError(
                "tests must list at least one vulnerable and one safe file "
                "(every rule needs a positive and a negative test)"
            )
        return self

    @property
    def display_title(self) -> str:
        return self.title or self.message.split(".")[0].strip()


class _LanguageRule(_RuleBase):
    languages: list[str]

    @field_validator("languages")
    @classmethod
    def _languages(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("languages must not be empty")
        unknown = [x for x in v if x not in KNOWN_LANGUAGES]
        if unknown:
            raise ValueError(f"unknown language(s): {', '.join(unknown)}")
        return v


class PatternRule(_LanguageRule):
    kind: Literal["pattern"] = "pattern"
    pattern: str | None = None
    pattern_either: list[str] | None = Field(default=None, alias="pattern-either")
    pattern_not: list[str] = Field(default_factory=list, alias="pattern-not")
    pattern_inside: list[str] = Field(default_factory=list, alias="pattern-inside")
    pattern_not_inside: list[str] = Field(default_factory=list, alias="pattern-not-inside")
    where: list[WhereClause] = Field(default_factory=list)

    @field_validator("pattern_not", "pattern_inside", "pattern_not_inside", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return _as_list(v)

    @model_validator(mode="after")
    def _one_anchor(self) -> PatternRule:
        if (self.pattern is None) == (self.pattern_either is None):
            raise ValueError("exactly one of 'pattern' or 'pattern-either' is required")
        if self.pattern_either is not None and not self.pattern_either:
            raise ValueError("'pattern-either' must not be empty")
        return self

    @property
    def anchors(self) -> list[str]:
        return [self.pattern] if self.pattern is not None else list(self.pattern_either or [])


class TaintRule(_LanguageRule):
    kind: Literal["taint"]
    sources: list[str]
    sinks: list[str]
    sanitizers: list[str] = Field(default_factory=list)
    propagators: list[str] = Field(default_factory=list)
    guards: list[str] = Field(default_factory=list)  # ownership evidence (tier B, IDOR)
    validators: list[str] = Field(default_factory=list)  # calls that validate when used in `if`

    @model_validator(mode="after")
    def _non_empty(self) -> TaintRule:
        if not self.sources or not self.sinks:
            raise ValueError("taint rules need at least one source and one sink")
        from vulnfab.core.taintspec import SpecError, TaintSpec

        try:
            TaintSpec.from_rule(
                self.sources,
                self.sinks,
                self.sanitizers,
                self.propagators,
                self.guards,
                self.validators,
            )
        except SpecError as exc:
            raise ValueError(str(exc)) from exc
        return self


class SchemaRule(_RuleBase):
    kind: Literal["schema"]
    check: str | None = None
    condition: str | None = None

    @model_validator(mode="after")
    def _check_or_condition(self) -> SchemaRule:
        if (self.check is None) == (self.condition is None):
            raise ValueError("exactly one of 'check' or 'condition' is required")
        if self.check is not None and not re.match(r"^[\w.]+:\w+$", self.check):
            raise ValueError("'check' must look like 'package.module:function'")
        if self.condition is not None:
            try:
                compile_expression(self.condition, SCHEMA_CONDITION_NAMES)
            except UnsafeExpression as exc:
                raise ValueError(f"unsafe or invalid condition: {exc}") from exc
        return self


class ScannerRule(_RuleBase):
    """Text scanner over file contents (secrets, env files, ...); see core/scannerrules.py."""

    kind: Literal["scanner"]
    scanner: str
    languages: list[str] = Field(default_factory=list)  # file languages to feed; empty = all

    @field_validator("scanner")
    @classmethod
    def _scanner(cls, v: str) -> str:
        if not re.match(r"^[\w.]+:\w+$", v):
            raise ValueError("'scanner' must look like 'package.module:function'")
        return v


class CrosscheckRule(_RuleBase):
    kind: Literal["crosscheck"]
    facts: Literal["DataAccess"]
    check: str

    @field_validator("check")
    @classmethod
    def _check(cls, v: str) -> str:
        if not re.match(r"^[\w.]+:\w+$", v):
            raise ValueError("'check' must look like 'package.module:function'")
        return v


Rule = Annotated[
    PatternRule | TaintRule | SchemaRule | ScannerRule | CrosscheckRule,
    Field(discriminator="kind"),
]


# --- loading --------------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleError:
    file: str
    line: int
    rule_id: str | None
    message: str

    def __str__(self) -> str:
        who = f" rule {self.rule_id!r}:" if self.rule_id else ""
        return f"{self.file}:{self.line}:{who} {self.message}"


class RuleLoadError(Exception):
    def __init__(self, errors: list[RuleError]) -> None:
        super().__init__("\n".join(str(e) for e in errors))
        self.errors = errors


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping as ``__line__``."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping = super().construct_mapping(node, deep=deep)
        mapping["__line__"] = node.start_mark.line + 1
        return mapping


def _strip_lines(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_lines(v) for k, v in value.items() if k != "__line__"}
    if isinstance(value, list):
        return [_strip_lines(v) for v in value]
    return value


def _format_pydantic(exc: ValidationError) -> list[str]:
    messages = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"] if p not in ("pattern", "taint", "schema"))
        msg = err["msg"].removeprefix("Value error, ")
        if err["type"] == "extra_forbidden":
            msg = "unknown field"
        elif err["type"] == "missing":
            msg = "field is required"
        messages.append(f"{loc}: {msg}" if loc else msg)
    return messages


AnyRule = PatternRule | TaintRule | SchemaRule | ScannerRule | CrosscheckRule


def parse_rules(text: str, filename: str = "<string>") -> tuple[list[AnyRule], list[RuleError]]:
    adapter: TypeAdapter[Any] = TypeAdapter(Rule)
    errors: list[RuleError] = []
    try:
        data = yaml.load(text, Loader=_LineLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        return [], [
            RuleError(filename, line, None, f"invalid YAML: {getattr(exc, 'problem', exc)}")
        ]
    if data is None:
        return [], []
    if isinstance(data, dict) and "rules" in data:
        items = data["rules"]
        if not isinstance(items, list):
            return [], [
                RuleError(filename, data.get("__line__", 1), None, "'rules' must be a list")
            ]
    elif isinstance(data, dict):
        items = [data]
    else:
        return [], [RuleError(filename, 1, None, "expected a mapping or a 'rules' list")]

    rules: list[AnyRule] = []
    for item in items:
        if not isinstance(item, dict):
            errors.append(RuleError(filename, 1, None, "each rule must be a mapping"))
            continue
        line = int(item.get("__line__", 1))
        payload = _strip_lines(item)
        payload.setdefault("kind", "pattern")
        rule_id = payload.get("id") if isinstance(payload.get("id"), str) else None
        try:
            rules.append(adapter.validate_python(payload))
        except ValidationError as exc:
            errors.extend(RuleError(filename, line, rule_id, m) for m in _format_pydantic(exc))
    return rules, errors


def load_rule_file(path: Path) -> tuple[list[Any], list[RuleError]]:
    return parse_rules(path.read_text(encoding="utf-8"), str(path))


def load_rules(paths: list[Path]) -> list[Any]:
    """Load every ``*.yml``/``*.yaml`` under the given files/directories.

    Raises :class:`RuleLoadError` listing *all* problems (including duplicate ids).
    """
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")]))
        elif p.is_file():
            files.append(p)
    rules: list[Any] = []
    errors: list[RuleError] = []
    seen: dict[str, str] = {}
    for f in files:
        loaded, errs = load_rule_file(f)
        errors.extend(errs)
        for rule in loaded:
            if rule.id in seen:
                errors.append(
                    RuleError(str(f), 1, rule.id, f"duplicate id (also in {seen[rule.id]})")
                )
                continue
            seen[rule.id] = str(f)
            rules.append(rule)
    if errors:
        raise RuleLoadError(errors)
    return rules
