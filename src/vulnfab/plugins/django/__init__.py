"""Django plugin: settings.py / models.py -> schema model, URL entrypoints, Django rule packs."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from vulnfab.core.models import (
    Column,
    Confidence,
    ConfigDoc,
    DataAccess,
    DispatchHint,
    Entrypoint,
    Finding,
    ParsedUnit,
    SchemaModel,
    SkippedFile,
    SourceFile,
    Table,
    TemplateUnit,
    Unresolved,
)
from vulnfab.core.parsing import ParseFailure, parse_file_cached
from vulnfab.plugins.base import RepoView
from vulnfab.plugins.django import pyconf, urlconf

_SETTINGS_RE = re.compile(r"(?:^|.*/)settings(?:\.py|/[^/]+\.py)$")
_MODELS_RE = re.compile(r"(?:^|.*/)models(?:\.py|/[^/]+\.py)$")
_SKIP_DIRS = ("site-packages/", "/venv/", "/.venv/", "node_modules/")
_REQUIREMENTS_RE = re.compile(
    r"(?:^|.*/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg)$"
)
_SENSITIVE_KINDS = ("CharField", "TextField", "BinaryField", "EmailField")


def _skip(path: str) -> bool:
    return any(marker in f"/{path}" for marker in _SKIP_DIRS)


class DjangoPlugin:
    name = "django"
    languages = ["python"]

    def detect(self, repo: RepoView) -> Confidence:
        paths = [p for p in (getattr(repo, "paths", None) or []) if not _skip(p)]
        if any(p.rsplit("/", 1)[-1] == "manage.py" for p in paths):
            try:
                if any(
                    "django" in repo.read_text(p).lower()
                    for p in paths
                    if p.rsplit("/", 1)[-1] == "manage.py"
                ):
                    return Confidence.HIGH
            except (OSError, KeyError):
                pass
        for p in paths:
            if _SETTINGS_RE.match(p):
                try:
                    if "INSTALLED_APPS" in repo.read_text(p):
                        return Confidence.HIGH
                except (OSError, KeyError):
                    continue
        for p in paths:
            if _REQUIREMENTS_RE.match(p):
                try:
                    if re.search(r"(?im)^\s*[\"']?django(?![\w-])", repo.read_text(p)):
                        return Confidence.MEDIUM
                except (OSError, KeyError):
                    continue
        return Confidence.LOW

    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit:
        unit = ParsedUnit()
        for sf in files:
            if sf.language != "python":
                continue
            try:
                unit.files[sf.path] = parse_file_cached(sf)
            except ParseFailure as exc:
                unit.skipped.append(SkippedFile(sf.path, exc.reason, exc.detail))
        return unit

    # --- schema: settings + models ---------------------------------------------------------

    def extract_schema(self, repo: RepoView) -> SchemaModel | None:
        paths = [p for p in (getattr(repo, "paths", None) or []) if not _skip(p)]
        settings = sorted(p for p in paths if _SETTINGS_RE.match(p))
        models = sorted(p for p in paths if _MODELS_RE.match(p))
        if not settings and not models:
            return None
        model = SchemaModel()
        for path in settings:
            read = pyconf.read_settings(repo.read_text(path))
            if read is None:
                model.unresolved.append(
                    Unresolved("parse_error", path, 1, "settings file is not valid Python 3")
                )
                continue
            doc = ConfigDoc(
                path,
                dict(read.values),
                {(k,): line for k, line in read.lines.items()},
                {"conditional": sorted(read.conditional), "mutated": sorted(read.mutated)},
            )
            model.configs[path] = doc
        self._load_models(model, repo, models)
        model.assumptions.append(
            "Django schema is read from models.py/settings.py without executing code; "
            "migrations are not applied and settings that depend on the environment are "
            "reported as dynamic."
        )
        return model

    @staticmethod
    def _load_models(model: SchemaModel, repo: RepoView, paths: list[str]) -> None:
        parsed: dict[str, list[pyconf.ModelClass]] = {}
        for path in paths:
            classes = pyconf.read_models(repo.read_text(path))
            if classes is None:
                model.unresolved.append(
                    Unresolved("parse_error", path, 1, "models file is not valid Python 3")
                )
                continue
            parsed[path] = classes
        by_name: dict[str, pyconf.ModelClass] = {}
        for classes in parsed.values():
            for c in classes:
                by_name.setdefault(c.name, c)
        # a class is a model if a base ends with "Model" or is a known model (fixpoint)
        is_model: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, cls in by_name.items():
                if name in is_model:
                    continue
                if any(
                    b.rsplit(".", 1)[-1].endswith(("Model", "AbstractUser", "AbstractBaseUser"))
                    or b.rsplit(".", 1)[-1] in is_model
                    for b in cls.bases
                ):
                    is_model.add(name)
                    changed = True

        def all_fields(
            cls: pyconf.ModelClass, seen: frozenset[str] = frozenset()
        ) -> list[pyconf.ModelField]:
            inherited: list[pyconf.ModelField] = []
            for base in cls.bases:
                parent = by_name.get(base.rsplit(".", 1)[-1])
                if parent is not None and parent.name not in seen and parent is not cls:
                    inherited.extend(all_fields(parent, seen | {cls.name}))
            return [*inherited, *cls.fields]

        for path, classes in parsed.items():
            parts = path.split("/")
            package = (
                parts[-2] if parts[-1] == "models.py" else (parts[-3] if len(parts) > 2 else "")
            )
            app = package or "default"
            for cls in classes:
                if cls.name not in is_model or cls.abstract:
                    continue
                table = Table(
                    name=cls.name.lower(),
                    schema=app,
                    file=path,
                    line=cls.line,
                    end_line=cls.end_line,
                )
                for f in all_fields(cls):
                    table.columns.append(
                        Column(
                            f.name,
                            f.kind,
                            nullable=f.null,
                            unique=f.unique,
                            sensitive_hint=bool(
                                pyconf.SENSITIVE_NAME.search(f.name) and f.kind in _SENSITIVE_KINDS
                            ),
                            references=f.target,
                        )
                    )
                model.tables[f"{app}.{cls.name.lower()}"] = table

    # --- contract stubs (filled in as the plugin grows) --------------------------------------

    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]:
        texts = {
            path: pf.source.decode("utf-8", errors="replace")
            for path, pf in unit.files.items()
            if pf.language == "python" and not _skip(path)
        }
        index = urlconf.build_index(texts)
        conf = _project_settings(texts)
        resolver = urlconf.ViewResolver(
            index, drf_default_auth=conf.drf_default_auth, login_middleware=conf.login_middleware
        )
        roots = _root_modules(index, conf.root_urlconf)
        found: list[Entrypoint] = []
        for route in urlconf.walk_urls(index, roots, resolver):
            entry = urlconf.to_entrypoint(route)
            if entry is not None:
                found.append(entry)
            elif route.unresolved:
                unit.unresolved.append(
                    Unresolved("django_view", route.file, route.line, route.unresolved)
                )
        return found

    def data_access(self, unit: ParsedUnit) -> list[DataAccess]:
        return []

    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]:
        return []

    def templates(self, repo: RepoView) -> list[TemplateUnit]:
        return []

    def rule_packs(self) -> list[Path]:
        return [Path(__file__).resolve().parents[2] / "rules" / "django"]

    def refine(
        self, raw: list[tuple[Finding, str]], model: SchemaModel
    ) -> list[tuple[Finding, str]]:
        """Use the models to judge IDOR candidates: rows without any owner relation are
        reference data, so fetching them by id is not an object-level authorization gap."""
        out: list[tuple[Finding, str]] = []
        for finding, symbol in raw:
            if finding.rule_id == "tpy-idor":
                table = _queried_table(finding.snippet, model)
                if table is not None and not _has_owner(table):
                    finding = replace(
                        finding,
                        confidence=Confidence.LOW,
                        message=f"{finding.message} (model {table.name} has no relation to a user, "
                        "so it may be shared reference data)",
                    )
            out.append((finding, symbol))
        return out

    def fixture_path(self, filename: str) -> str | None:
        if filename.startswith("settings"):
            return "proj/settings.py"
        if filename.startswith("models"):
            return "app/models.py"
        return None


@dataclass
class _ProjectConf:
    root_urlconf: str | None = None
    drf_default_auth: bool = False
    login_middleware: bool = False


def _project_settings(texts: dict[str, str]) -> _ProjectConf:
    conf = _ProjectConf()
    for path, text in texts.items():
        if not _SETTINGS_RE.match(path):
            continue
        read = pyconf.read_settings(text)
        if read is None:
            continue
        root = read.values.get("ROOT_URLCONF")
        if isinstance(root, str):
            conf.root_urlconf = root
        for name in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
            middleware = read.values.get(name)
            if isinstance(middleware, (list, tuple)) and any(
                isinstance(m, str) and m.endswith("LoginRequiredMiddleware") for m in middleware
            ):
                conf.login_middleware = True
        rest = read.values.get("REST_FRAMEWORK")
        if isinstance(rest, dict):
            perms = rest.get("DEFAULT_PERMISSION_CLASSES")
            if isinstance(perms, (list, tuple)) and perms:
                conf.drf_default_auth = not any(
                    isinstance(p, str) and p.endswith("AllowAny") for p in perms
                )
    return conf


def _root_modules(index: urlconf.UrlIndex, root_urlconf: str | None) -> list[urlconf.Module]:
    if root_urlconf:
        module = index.by_dotted(root_urlconf)
        if module is not None:
            return [module]
    modules = index.url_modules()
    included: set[str] = set()
    for module in modules:
        imports = urlconf._imports(module, index)
        for route in urlconf._collect_routes(module):
            if route.include is not None:
                child = urlconf._resolve_include(route, index, imports)
                if child is not None:
                    included.add(child.path)
    roots = [m for m in modules if m.path not in included]
    return roots or modules


_QUERIED = re.compile(r"(\w+)\.objects\.|get_object_or_404\(\s*(\w+)|get_list_or_404\(\s*(\w+)")
_OWNER_NAMES = re.compile(
    r"^(user|owner|author|created_by|creator|member|account|profile|users?_?\w*)$", re.I
)


def _queried_table(snippet: str, model: SchemaModel):  # type: ignore[no-untyped-def]
    match = _QUERIED.search(snippet)
    if not match:
        return None
    name = next(g for g in match.groups() if g).lower()
    candidates = [t for t in model.tables.values() if t.name == name]
    return candidates[0] if len(candidates) == 1 else None


def _has_owner(table) -> bool:  # type: ignore[no-untyped-def]
    for column in table.columns:
        target = column.references or ""
        if "User" in target or "AUTH_USER_MODEL" in target or _OWNER_NAMES.match(column.name):
            return True
    return False
