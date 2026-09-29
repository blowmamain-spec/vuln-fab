"""Resolve Django URL configuration to view definitions and their authentication (WP-6.2).

Reads ``urls.py`` files and views with :mod:`ast`; nothing is imported or executed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from vulnfab.core.models import AuthInfo, Entrypoint

AUTH_DECORATORS = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
    "superuser_required",
    "admin_required",
    "jwt_required",
    "token_required",
    "authentication_required",
}
AUTH_MIXINS = {
    "LoginRequiredMixin",
    "PermissionRequiredMixin",
    "UserPassesTestMixin",
    "StaffuserRequiredMixin",
    "SuperuserRequiredMixin",
    "AccessMixin",
}
INLINE_AUTH = re.compile(
    r"\.(is_authenticated|is_staff|is_superuser|has_perm|has_perms|is_anonymous)\b|"
    r"\bget_object_or_404\([^)]*user\b|\brequest\.user\s*(==|!=|in\b)"
)
WRITE_CALL = re.compile(
    r"\.(save|delete|create|update|bulk_create|bulk_update|get_or_create|update_or_create)\("
)
ORM_READ = re.compile(r"\.objects\.(get|filter|all|first)\(|get_object_or_404\(|get_list_or_404\(")
PUBLIC_NAME = re.compile(
    r"^(index|home|about|contact|login|logout|signin|signout|signup|register|health|healthz|ping|"
    r"robots|sitemap|password_reset\w*|forgot\w*|reset_password|tutorials?|landing|status)$",
    re.I,
)
_NAMED_GROUP = re.compile(r"\(\?P<(\w+)>")
_CONVERTER = re.compile(r"<(?:\w+:)?(\w+)>")
PERMISSIVE_DRF = {"AllowAny"}


@dataclass
class Module:
    path: str
    tree: ast.Module
    text: str
    dotted: str


@dataclass
class Route:
    pattern: str
    line: int
    file: str
    target: ast.AST | None  # view expression
    include: ast.AST | None
    module: Module


@dataclass
class ViewInfo:
    file: str
    line: int
    qualname: str
    kind: str  # function | class
    auth: AuthInfo
    traits: tuple[str, ...]


class UrlIndex:
    """Python modules of the project, parsed lazily by dotted name."""

    def __init__(self, files: dict[str, str]) -> None:
        self.texts = files
        self._dotted = {path: _dotted_name(path) for path in files}
        self._modules: dict[str, Module | None] = {}

    def module(self, path: str) -> Module | None:
        if path not in self._modules:
            try:
                tree = ast.parse(self.texts[path])
                self._modules[path] = Module(path, tree, self.texts[path], self._dotted[path])
            except (SyntaxError, ValueError, RecursionError):
                self._modules[path] = None
        return self._modules[path]

    def by_dotted(self, dotted: str) -> Module | None:
        dotted = dotted.strip(".")
        if not dotted:
            return None
        exact = [p for p, d in self._dotted.items() if d == dotted]
        if exact:
            return self.module(exact[0])
        tail = "." + dotted
        found = [p for p, d in self._dotted.items() if ("." + d).endswith(tail)]
        return self.module(found[0]) if len(found) == 1 else None

    def url_modules(self) -> list[Module]:
        out: list[Module] = []
        for path, text in self.texts.items():
            if "urlpatterns" in text:
                mod = self.module(path)
                if mod is not None:
                    out.append(mod)
        return out


def _dotted_name(path: str) -> str:
    base = path[:-3] if path.endswith(".py") else path
    if base.endswith("/__init__"):
        base = base[: -len("/__init__")]
    return base.replace("/", ".")


def build_index(files: dict[str, str]) -> UrlIndex:
    return UrlIndex(files)


def _imports(module: Module, index: UrlIndex) -> dict[str, str]:
    """local name -> dotted target (module, or module.attr)."""
    out: dict[str, str] = {}
    pkg = module.dotted.rsplit(".", 1)[0] if "." in module.dotted else ""
    if module.path.endswith("__init__.py"):
        pkg = module.dotted
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
                if not alias.asname:
                    out[alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = pkg.split(".") if pkg else []
                parts = parts[: max(len(parts) - (node.level - 1), 0)]
                base = ".".join([*parts, base] if base else parts)
            for alias in node.names:
                out[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name
    return out


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("r", "_")
    ):
        return _const_str(node.args[0]) if node.args else None
    return None


def _attr_chain(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_chain(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


ROUTE_FUNCS = {"path", "re_path", "url"}


def _collect_routes(module: Module) -> list[Route]:
    routes: list[Route] = []

    def take(expr: ast.AST) -> None:
        if isinstance(expr, (ast.List, ast.Tuple)):
            for e in expr.elts:
                take(e)
        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            take(expr.left)
            take(expr.right)
        elif isinstance(expr, ast.Call):
            name = _attr_chain(expr.func) or ""
            short = name.rsplit(".", 1)[-1]
            if short == "patterns":  # Django < 1.10: patterns('prefix', url(...), ...)
                for a in expr.args[1:]:
                    take(a)
            elif short in ROUTE_FUNCS and expr.args:
                pattern = _const_str(expr.args[0]) or ""
                view = expr.args[1] if len(expr.args) > 1 else None
                include = None
                if isinstance(view, ast.Call) and (_attr_chain(view.func) or "").endswith(
                    "include"
                ):
                    include, view = (view.args[0] if view.args else None), None
                routes.append(Route(pattern, expr.lineno, module.path, view, include, module))
            elif short == "include" and expr.args:
                routes.append(Route("", expr.lineno, module.path, None, expr.args[0], module))
        elif isinstance(expr, ast.Name):
            # urlpatterns built from another list variable in the same module
            for node in module.tree.body:
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == expr.id for t in node.targets
                ):
                    take(node.value)

    for node in module.tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets)
            or (
                isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "urlpatterns"
            )
        ):
            take(node.value)
    return routes


def _resolve_include(route: Route, index: UrlIndex, imports: dict[str, str]) -> Module | None:
    node = route.include
    if isinstance(node, ast.Tuple) and node.elts:
        node = node.elts[0]
    text = _const_str(node)
    if text is not None:
        return index.by_dotted(text)
    chain = _attr_chain(node) if node is not None else None
    if chain:
        head, _, rest = chain.partition(".")
        target = imports.get(head, head) + (f".{rest}" if rest else "")
        return index.by_dotted(target)
    return None


@dataclass
class ResolvedRoute:
    route: str
    line: int
    file: str
    view: ViewInfo | None
    params: tuple[str, ...]
    unresolved: str = ""


def walk_urls(index: UrlIndex, roots: list[Module], views: ViewResolver) -> list[ResolvedRoute]:
    out: list[ResolvedRoute] = []

    def visit(module: Module, prefix: str, params: tuple[str, ...], seen: frozenset[str]) -> None:
        if module.path in seen:
            return
        imports = _imports(module, index)
        for route in _collect_routes(module):
            full = prefix + route.pattern
            here = tuple(
                dict.fromkeys(
                    [
                        *params,
                        *_NAMED_GROUP.findall(route.pattern),
                        *_CONVERTER.findall(route.pattern),
                    ]
                )
            )
            if route.include is not None:
                child = _resolve_include(route, index, imports)
                if child is not None:
                    visit(child, full, here, seen | {module.path})
                continue
            if route.target is None:
                continue
            info, why = views.resolve(route.target, module, imports)
            out.append(ResolvedRoute(full, route.line, module.path, info, here, why))

    for root in roots:
        visit(root, "", (), frozenset())
    return out


class ViewResolver:
    def __init__(
        self, index: UrlIndex, drf_default_auth: bool = False, login_middleware: bool = False
    ) -> None:
        self.index = index
        self.drf_default_auth = drf_default_auth
        self.login_middleware = login_middleware
        self._cache: dict[tuple[str, str], ViewInfo | None] = {}

    def resolve(
        self, node: ast.AST, module: Module, imports: dict[str, str]
    ) -> tuple[ViewInfo | None, str]:
        if isinstance(node, ast.Call):
            called = _attr_chain(node.func) or ""
            if called.endswith(".as_view") and isinstance(node.func, ast.Attribute):
                node = node.func.value
            else:
                return None, f"view built by call {called or '?'}()"
        text = _const_str(node)
        if text is not None:
            mod_name, _, attr = text.rpartition(".")
            return self._lookup(mod_name, attr), "" if mod_name else "unqualified view string"
        chain = _attr_chain(node)
        if not chain:
            return None, "view expression is not a name"
        head, _, rest = chain.partition(".")
        target = imports.get(head)
        if target is None:
            info = self._local(module, chain)
            return info, "" if info else f"{chain} is not defined or imported here"
        dotted = target + (f".{rest}" if rest else "")
        mod_name, _, attr = dotted.rpartition(".")
        info = self._lookup(mod_name, attr)
        if info is None and rest:
            # views.Class.method or module.attr chains
            mod_name2, _, attr2 = dotted.rpartition(".")
            info = self._lookup(mod_name2.rpartition(".")[0], mod_name2.rpartition(".")[2])
        return info, "" if info else f"cannot locate {dotted}"

    def _lookup(self, mod_name: str, attr: str) -> ViewInfo | None:
        module = self.index.by_dotted(mod_name)
        if module is None:
            return None
        return self._local(module, attr)

    def _local(self, module: Module, name: str) -> ViewInfo | None:
        key = (module.path, name)
        if key in self._cache:
            return self._cache[key]
        info: ViewInfo | None = None
        for node in module.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                info = self._function(module, node)
                break
            if isinstance(node, ast.ClassDef) and node.name == name:
                info = self._class(module, node)
                break
        self._cache[key] = info
        return info

    # --- analysis -------------------------------------------------------------------------

    def _decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
        names: list[str] = []
        for d in node.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            chain = _attr_chain(target) or ""
            names.append(chain.rsplit(".", 1)[-1])
            if chain.endswith("method_decorator") and isinstance(d, ast.Call) and d.args:
                inner = d.args[0]
                inner_target = inner.func if isinstance(inner, ast.Call) else inner
                names.append((_attr_chain(inner_target) or "").rsplit(".", 1)[-1])
        return names

    def _traits(self, module: Module, node: ast.AST, decorators: list[str]) -> tuple[str, ...]:
        source = ast.get_source_segment(module.text, node) or ""
        traits: list[str] = []
        if WRITE_CALL.search(source):
            traits.append("writes")
        if ORM_READ.search(source):
            traits.append("reads-data")
        if "csrf_exempt" in decorators:
            traits.append("csrf-exempt")
        return tuple(traits)

    def _auth_from_names(self, names: set[str], source: str) -> AuthInfo:
        hit = sorted(names & (AUTH_DECORATORS | AUTH_MIXINS))
        if hit:
            return AuthInfo(True, hit[0])
        if self.login_middleware:
            return AuthInfo(True, "LoginRequiredMiddleware")
        if INLINE_AUTH.search(source):
            return AuthInfo(None, "inline user check")
        return AuthInfo(False, "")

    def _function(self, module: Module, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ViewInfo:
        decorators = self._decorators(node)
        source = ast.get_source_segment(module.text, node) or ""
        names = set(decorators)
        auth = self._auth_from_names(names, source)
        if "api_view" in names and auth.required is not True:
            perm = _drf_permissions(node)
            if perm is not None and not (set(perm) & PERMISSIVE_DRF):
                auth = AuthInfo(True, "permission_classes")
            elif perm is None and self.drf_default_auth:
                auth = AuthInfo(True, "DEFAULT_PERMISSION_CLASSES")
        return ViewInfo(
            module.path,
            node.lineno,
            node.name,
            "function",
            auth,
            self._traits(module, node, decorators),
        )

    def _class(self, module: Module, node: ast.ClassDef) -> ViewInfo:
        decorators = self._decorators(node)
        bases = {(_attr_chain(b) or "").rsplit(".", 1)[-1] for b in node.bases}
        names = set(decorators) | bases
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names |= set(self._decorators(item)) if item.name == "dispatch" else set()
        source = ast.get_source_segment(module.text, node) or ""
        auth = self._auth_from_names(names, source)
        if auth.required is not True:
            perms = _class_permissions(node)
            if perms is not None and not (set(perms) & PERMISSIVE_DRF):
                auth = AuthInfo(True, "permission_classes")
            elif perms is None and self.drf_default_auth and bases & DRF_BASES:
                auth = AuthInfo(True, "DEFAULT_PERMISSION_CLASSES")
        return ViewInfo(
            module.path,
            node.lineno,
            node.name,
            "class",
            auth,
            self._traits(module, node, decorators),
        )


DRF_BASES = {
    "APIView", "ViewSet", "ModelViewSet", "ReadOnlyModelViewSet", "GenericViewSet",
    "GenericAPIView", "ListAPIView", "CreateAPIView", "RetrieveAPIView", "UpdateAPIView",
    "DestroyAPIView", "ListCreateAPIView", "RetrieveUpdateAPIView", "RetrieveDestroyAPIView",
    "RetrieveUpdateDestroyAPIView",
}  # fmt: skip


def _names_in(node: ast.AST) -> list[str]:
    return [
        (_attr_chain(n) or "").rsplit(".", 1)[-1]
        for n in ast.walk(node)
        if isinstance(n, (ast.Name, ast.Attribute))
    ]


def _class_permissions(node: ast.ClassDef) -> list[str] | None:
    for item in node.body:
        if isinstance(item, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "permission_classes" for t in item.targets
        ):
            return _names_in(item.value)
    return None


def _drf_permissions(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str] | None:
    for d in node.decorator_list:
        if isinstance(d, ast.Call) and (_attr_chain(d.func) or "").endswith("permission_classes"):
            return _names_in(d)
    return None


def to_entrypoint(r: ResolvedRoute) -> Entrypoint | None:
    if r.view is None:
        return None
    v = r.view
    kind = "django-view" if v.kind == "function" else "django-class-view"
    return Entrypoint(
        kind=kind,
        file=v.file,
        line=v.line,
        handler=v.qualname,
        params=tuple(dict.fromkeys(r.params)),
        auth=v.auth,
        route=r.route,
        route_file=r.file,
        route_line=r.line,
        traits=v.traits,
    )
