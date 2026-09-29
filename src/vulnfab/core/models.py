"""Core data model: findings, IR facts, and the framework-neutral schema model.

See docs/spec.md for the contract these types implement.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from typing import Any, Literal


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]

    @property
    def rank(self) -> int:
        return self.weight


class Confidence(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> float:
        return _CONFIDENCE_WEIGHT[self]

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    def lowered(self, steps: int = 1) -> Confidence:
        order = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
        return order[min(order.index(self) + max(steps, 0), len(order) - 1)]


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_CONFIDENCE_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}
_CONFIDENCE_RANK = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}

Tier = Literal["A", "B", "C"]
TraceKind = Literal["source", "propagate", "call", "return", "sink", "schema", "policy"]


@dataclass(frozen=True)
class TraceStep:
    file: str
    line: int
    kind: TraceKind
    detail: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    cwe: tuple[str, ...]
    owasp: str | None
    severity: Severity
    confidence: Confidence
    tier: Tier | None
    file: str
    line: int
    end_line: int
    snippet: str
    trace: tuple[TraceStep, ...] = ()
    unresolved_hops: int = 0
    fix: str | None = None
    fingerprint: str = ""

    @property
    def priority(self) -> float:
        return self.severity.weight * self.confidence.weight


# --- Source files and IR facts -------------------------------------------------------------


@dataclass(frozen=True)
class SourceFile:
    path: str  # relative to scan root, "/" separators
    language: str
    text: str
    sha256: str


@dataclass(frozen=True)
class AuthInfo:
    required: bool | None  # None = unknown
    mechanism: str = ""


@dataclass(frozen=True)
class Entrypoint:
    kind: str
    file: str
    line: int
    handler: str
    params: tuple[str, ...] = ()
    auth: AuthInfo | None = None


@dataclass(frozen=True)
class DispatchHint:
    file: str
    line: int
    targets: tuple[str, ...]


ClientKind = Literal["anon", "user", "service_role", "unknown"]
DataOp = Literal["select", "insert", "update", "delete", "upsert", "rpc"]


@dataclass(frozen=True)
class DataAccess:
    table: str
    schema: str | None
    op: DataOp
    file: str
    line: int
    filter_columns: tuple[str, ...] = ()
    client_kind: ClientKind = "unknown"


@dataclass(frozen=True)
class Unresolved:
    kind: str  # dynamic_call | dynamic_sql | do_block | import | ...
    file: str
    line: int
    detail: str = ""


@dataclass
class ParsedFile:
    path: str
    language: str
    tree: Any = None  # tree-sitter Tree (or plugin-specific parse result)


@dataclass
class ParsedUnit:
    files: dict[str, ParsedFile] = field(default_factory=dict)
    unresolved: list[Unresolved] = field(default_factory=list)


@dataclass(frozen=True)
class TemplateUnit:
    file: str
    kind: str  # django | blade
    text: str


# --- Schema model (framework-neutral) ------------------------------------------------------


@dataclass
class Column:
    name: str
    type: str
    nullable: bool = True
    default: str | None = None
    unique: bool = False
    sensitive_hint: bool = False


PolicyCommand = Literal["all", "select", "insert", "update", "delete"]


@dataclass
class Policy:
    name: str
    table: str
    permissive: bool = True
    command: PolicyCommand = "all"
    roles: tuple[str, ...] = ("public",)
    using_expr: str | None = None
    check_expr: str | None = None
    file: str = ""
    line: int = 0


@dataclass
class Grant:
    role: str
    privileges: frozenset[str]
    with_grant: bool = False
    file: str = ""
    line: int = 0


@dataclass
class Table:
    name: str
    schema: str = "public"
    columns: list[Column] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    rls_enabled: bool = False
    rls_forced: bool = False
    policies: list[Policy] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    file: str = ""
    line: int = 0

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class Function:
    name: str
    schema: str = "public"
    security_definer: bool = False
    search_path: str | None = None
    language: str = "sql"
    body: str = ""
    file: str = ""
    line: int = 0


@dataclass
class View:
    name: str
    schema: str = "public"
    security_invoker: bool = False
    definition: str = ""
    file: str = ""
    line: int = 0


@dataclass
class DefaultPrivilege:
    role: str
    schema: str | None
    object_type: str
    privileges: frozenset[str]
    grantee: str = ""


@dataclass
class Bucket:
    name: str
    public: bool = False
    file: str = ""
    line: int = 0


@dataclass
class SchemaModel:
    tables: dict[str, Table] = field(default_factory=dict)  # key: "schema.name"
    functions: dict[str, Function] = field(default_factory=dict)
    views: dict[str, View] = field(default_factory=dict)
    default_privileges: list[DefaultPrivilege] = field(default_factory=list)
    buckets: dict[str, Bucket] = field(default_factory=dict)
    unresolved: list[Unresolved] = field(default_factory=list)


# --- Serialisation -------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses / enums / tuples / sets into JSON-serialisable structures."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(v) for v in obj)
    return obj
