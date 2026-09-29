"""Laravel route files -> entrypoints with authentication and CSRF facts (WP-7.2)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, replace

from tree_sitter import Node

from vulnfab.core.models import AuthInfo, Entrypoint, ParsedFile, Unresolved
from vulnfab.plugins.laravel import phpast as ast

HTTP_VERBS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "any",
    "match",
    "view",
    "redirect",
    "fallback",
}
RESOURCE_ACTIONS = {
    "index": ("GET", ""),
    "create": ("GET", "/create"),
    "store": ("POST", ""),
    "show": ("GET", "/{id}"),
    "edit": ("GET", "/{id}/edit"),
    "update": ("PUT", "/{id}"),
    "destroy": ("DELETE", "/{id}"),
}
API_EXCLUDED = {"create", "edit"}
AUTH_MIDDLEWARE = re.compile(
    r"^(auth(\.\w+)?|can|cannot|role|permission|permissions|verified|admin|is_?admin|"
    r"sanctum|jwt(\.\w+)?|passport|password\.confirm|signed)$",
    re.I,
)
INLINE_AUTH = re.compile(
    r"Auth::(user|id|check|guard)|\bauth\(\)|\$request->user\(|\$this->authorize\(|Gate::|"
    r"->can\(|abort_(?:if|unless)\(|Auth::|->authorizeResource\(|\$this->middleware\('auth"
)
WRITE = re.compile(
    r"->(save|delete|update|create|fill|attach|detach|sync|forceDelete|restore|increment|decrement|"
    r"store|storeAs|move)\(|::(create|destroy|insert|forceCreate|updateOrCreate|firstOrCreate|"
    r"upsert|truncate)\(|DB::(insert|update|delete|statement|unprepared)\(|Storage::(put|delete)\("
)
READ = re.compile(
    r"::(find|findOrFail|where|first|all|query|with|firstOrFail)\(|->(first|get|paginate|findOrFail|"
    r"firstOrFail)\(|DB::(select|table)\(|Storage::(get|download)\(|response\(\)->download"
)
PUBLIC_NAME = re.compile(
    r"^(index|home|welcome|login|logout|register|store_?login|create_?account|forgot\w*|reset\w*|"
    r"health\w*|ping|status|about|contact|__invoke|verify\w*|callback|redirect|show_?login\w*|"
    r"authenticate|webhook\w*)$",
    re.I,
)
PARAM_RE = re.compile(r"\{(\w+)\??\}")


@dataclass(frozen=True)
class Ctx:
    prefix: str = ""
    middleware: tuple[str, ...] = ()
    without: tuple[str, ...] = ()
    controller: str | None = None
    namespace: str = ""
    name: str = ""


@dataclass
class RouteDef:
    verb: str
    uri: str
    file: str
    line: int
    middleware: tuple[str, ...]
    without: tuple[str, ...]
    cls: str | None  # class name as written / resolved
    method: str | None
    closure: Node | None
    closure_file: str = ""
    only: set[str] | None = None
    action: str = ""
    node: Node | None = None


@dataclass
class ControllerInfo:
    file: str
    line: int
    methods: dict[str, tuple[Node, bytes]]
    ctor_middleware: list[tuple[str, set[str] | None, set[str] | None]]


def _imports(root: Node, source: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in ast.walk(root):
        if node.type == "namespace_use_clause":
            name = ast.text(node, source)
            alias = None
            if " as " in name:
                name, alias = (x.strip() for x in name.split(" as ", 1))
            name = name.lstrip("\\")
            out[alias or name.rsplit("\\", 1)[-1]] = name
    return out


def _mw_list(node: Node | None, source: bytes) -> list[str]:
    values = ast.string_list(node, source)
    if values is not None:
        return values
    if node is not None and node.type == "array_creation_expression":
        out: list[str] = []
        for _, item in ast.array_items(node, source):
            out.extend(_mw_list(item, source))
        return out
    cls = ast.class_ref(node, source) if node is not None else None
    return [cls] if cls else []


class RouteCollector:
    def __init__(self, unresolved: list[Unresolved]) -> None:
        self.routes: list[RouteDef] = []
        self.unresolved = unresolved

    def collect(self, path: str, pf: ParsedFile) -> None:
        source = pf.source
        self.path, self.source = path, source
        self.imports = _imports(pf.tree.root_node, source)
        base = Ctx()
        if path.endswith("routes/api.php"):
            base = Ctx(prefix="api")
        self._block(pf.tree.root_node, base)

    # --- statements ---------------------------------------------------------------------------

    def _block(self, node: Node, ctx: Ctx) -> None:
        for child in node.children:
            if child.type == "expression_statement":
                named = [c for c in child.children if c.is_named]
                if named:
                    self._expression(named[0], ctx)
            elif child.type in ("compound_statement", "program"):
                self._block(child, ctx)

    def _expression(self, expr: Node, ctx: Ctx) -> None:
        chain = ast.chain_of(expr, self.source)
        if chain is None or chain.root != "Route" or not chain.scoped:
            return
        state = ctx
        route_indexes: list[int] = []
        for link in chain.links:
            name = link.name
            args = link.args
            if name == "middleware":
                state = replace(
                    state,
                    middleware=(
                        *state.middleware,
                        *_mw_list(args[0] if args else None, self.source),
                    ),
                )
                self._apply_to(
                    route_indexes, add_middleware=_mw_list(args[0] if args else None, self.source)
                )
            elif name == "withoutMiddleware":
                skipped = _mw_list(args[0] if args else None, self.source)
                state = replace(state, without=(*state.without, *skipped))
                self._apply_to(route_indexes, add_without=skipped)
            elif name == "prefix" and args:
                prefix = ast.string_value(args[0], self.source) or ""
                state = replace(state, prefix=_join(state.prefix, prefix))
            elif name == "name" and args:
                state = replace(
                    state, name=state.name + (ast.string_value(args[0], self.source) or "")
                )
            elif name == "namespace" and args:
                state = replace(state, namespace=ast.string_value(args[0], self.source) or "")
            elif name == "controller" and args:
                ref = ast.class_ref(args[0], self.source)
                state = replace(state, controller=ref or state.controller)
            elif name in ("only", "except") and route_indexes:
                names = ast.string_list(args[0] if args else None, self.source) or []
                self._filter_resource(route_indexes, name, set(names))
            elif name == "group":
                self._group(state, args)
            elif name == "resource" or name == "apiResource":
                route_indexes = self._resource(state, link, name == "apiResource")
            elif name == "resources" or name == "apiResources":
                self.unresolved.append(
                    Unresolved(
                        "route_resources",
                        self.path,
                        ast.line(link.node, self.source),
                        "Route::resources() array not expanded",
                    )
                )
            elif name in HTTP_VERBS:
                route_indexes = self._verb(state, link)
            # where(), name(), domain(), scopeBindings() ... do not change auth facts

    def _group(self, ctx: Ctx, args: list[Node]) -> None:
        if not args:
            return
        closure = args[-1]
        if closure.type in ("anonymous_function", "arrow_function"):
            body = closure.child_by_field_name("body")
            if body is not None:
                self._block(body, ctx)
        else:
            self.unresolved.append(
                Unresolved(
                    "route_group",
                    self.path,
                    ast.line(closure, self.source),
                    "group() loads routes from a file or expression",
                )
            )

    def _apply_to(
        self,
        indexes: list[int],
        add_middleware: list[str] | None = None,
        add_without: list[str] | None = None,
    ) -> None:
        for i in indexes:
            route = self.routes[i]
            if add_middleware:
                route.middleware = (*route.middleware, *add_middleware)
            if add_without:
                route.without = (*route.without, *add_without)

    def _filter_resource(self, indexes: list[int], mode: str, names: set[str]) -> None:
        keep = []
        for i in indexes:
            route = self.routes[i]
            allowed = route.action in names if mode == "only" else route.action not in names
            if allowed:
                keep.append(i)
            else:
                route.action = "<removed>"
        for i in indexes:
            if self.routes[i].action == "<removed>":
                self.routes[i].verb = ""

    def _resource(self, ctx: Ctx, link: ast.Link, api: bool) -> list[int]:
        name = ast.string_value(link.args[0], self.source) if link.args else None
        cls = ast.class_ref(link.args[1], self.source) if len(link.args) > 1 else None
        if not name or not cls:
            return []
        indexes: list[int] = []
        for action, (verb, suffix) in RESOURCE_ACTIONS.items():
            if api and action in API_EXCLUDED:
                continue
            uri = _join(
                ctx.prefix,
                name + suffix.replace("{id}", "{" + name.rsplit("/", 1)[-1].rstrip("s") + "}"),
            )
            self.routes.append(
                RouteDef(
                    verb,
                    uri,
                    self.path,
                    ast.line(link.node, self.source),
                    ctx.middleware,
                    ctx.without,
                    cls,
                    action,
                    None,
                    action=action,
                    node=link.node,
                )
            )
            indexes.append(len(self.routes) - 1)
        return indexes

    def _verb(self, ctx: Ctx, link: ast.Link) -> list[int]:
        args = link.args
        verb = link.name.upper()
        if link.name == "match" and len(args) >= 2:
            verbs = ast.string_list(args[0], self.source) or ["GET"]
            verb = "|".join(v.upper() for v in verbs)
            args = args[1:]
        uri = ast.string_value(args[0], self.source) if args else ""
        uri = _join(ctx.prefix, uri or "")
        target = args[1] if len(args) > 1 else None
        cls: str | None = None
        method: str | None = None
        closure: Node | None = None
        if target is not None:
            if target.type in ("anonymous_function", "arrow_function"):
                closure = target
            elif target.type == "array_creation_expression":
                items = [v for _, v in ast.array_items(target, self.source)]
                if len(items) == 2:
                    cls = ast.class_ref(items[0], self.source)
                    method = ast.string_value(items[1], self.source)
            elif ast.class_ref(target, self.source):
                cls, method = ast.class_ref(target, self.source), "__invoke"
            else:
                text = ast.string_value(target, self.source)
                if text and "@" in text:
                    cls, method = text.split("@", 1)
                elif text and ctx.controller:
                    cls, method = ctx.controller, text
        if cls is None and method and ctx.controller:
            cls = ctx.controller
        if cls is None and closure is None and link.name in ("view", "redirect", "fallback"):
            return []  # static views / redirects handle no data
        if cls is None and closure is None:
            self.unresolved.append(
                Unresolved(
                    "route_handler",
                    self.path,
                    ast.line(link.node, self.source),
                    f"handler of {verb} {uri} not understood",
                )
            )
            return []
        self.routes.append(
            RouteDef(
                verb,
                uri,
                self.path,
                ast.line(link.node, self.source),
                ctx.middleware,
                ctx.without,
                cls,
                method,
                closure,
                closure_file=self.path,
                node=link.node,
            )
        )
        return [len(self.routes) - 1]


def _join(prefix: str, uri: str) -> str:
    joined = "/".join(p.strip("/") for p in (prefix, uri) if p and p.strip("/"))
    return joined


# --- controllers -------------------------------------------------------------------------------


def _ctor_middleware(
    cls_node: Node, source: bytes
) -> list[tuple[str, set[str] | None, set[str] | None]]:
    out: list[tuple[str, set[str] | None, set[str] | None]] = []
    for method in ast.walk(cls_node):
        if (
            method.type != "method_declaration"
            or ast.text(method.child_by_field_name("name"), source) != "__construct"
        ):
            continue
        for call in ast.walk(method):
            if call.type != "member_call_expression":
                continue
            parent = call.parent
            if (
                parent is not None
                and parent.type == "member_call_expression"
                and parent.child_by_field_name("object") == call
            ):
                continue  # only the outermost call of a chain
            chain = ast.chain_of(call, source)
            if (
                chain is None
                or chain.root != "this"
                or not chain.links
                or chain.links[0].name != "middleware"
            ):
                continue
            names = _mw_list(chain.links[0].args[0] if chain.links[0].args else None, source)
            only = except_ = None
            for link in chain.links[1:]:
                values = set(ast.string_list(link.args[0], source) or []) if link.args else set()
                values |= {v for v in (ast.string_value(a, source) for a in link.args[1:]) if v}
                if link.name == "only":
                    only = values
                elif link.name == "except":
                    except_ = values
            out.extend((n, only, except_) for n in names)
    return out


def index_controllers(files: dict[str, ParsedFile]) -> dict[str, ControllerInfo]:
    """class short name (and FQN when namespaced) -> methods; controllers only."""
    out: dict[str, ControllerInfo] = {}
    for path, pf in files.items():
        source = pf.source
        if b"Controller" not in source:
            continue
        namespace = ""
        for node in ast.walk(pf.tree.root_node):
            if node.type == "namespace_definition":
                namespace = ast.text(node.child_by_field_name("name"), source)
            elif node.type == "class_declaration":
                name = ast.text(node.child_by_field_name("name"), source)
                if not name.endswith("Controller"):
                    continue
                methods = {
                    ast.text(m.child_by_field_name("name"), source): (m, source)
                    for m in ast.walk(node)
                    if m.type == "method_declaration"
                }
                info = ControllerInfo(
                    path, ast.line(node, source), methods, _ctor_middleware(node, source)
                )
                out[name] = info
                if namespace:
                    out[f"{namespace}\\{name}"] = info
    return out


def csrf_except(files: dict[str, ParsedFile]) -> list[str]:
    for path, pf in files.items():
        if not path.endswith("VerifyCsrfToken.php"):
            continue
        for node in ast.walk(pf.tree.root_node):
            if node.type == "property_element":
                var = next((c for c in node.children if c.type == "variable_name"), None)
                if var is not None and ast.text(var, pf.source).lstrip("$") == "except":
                    value = next(
                        (c for c in node.children if c.is_named and c.type != "variable_name"), None
                    )
                    return ast.string_list(value, pf.source) or []
    return []


def _resolve(cls: str, imports: dict[str, str]) -> list[str]:
    """Candidate keys for the controller index, most specific first."""
    fqn = imports.get(cls.split("\\")[0])
    candidates = []
    if fqn:
        candidates.append(fqn if "\\" not in cls else fqn + "\\" + cls.split("\\", 1)[1])
    candidates.append(cls.lstrip("\\"))
    candidates.append(cls.rsplit("\\", 1)[-1])
    return candidates


def to_entrypoints(
    routes: list[RouteDef],
    controllers: dict[str, ControllerInfo],
    imports_by_file: dict[str, dict[str, str]],
    sources: dict[str, bytes],
    csrf_patterns: list[str],
    unresolved: list[Unresolved],
) -> list[Entrypoint]:
    out: list[Entrypoint] = []
    for route in routes:
        if not route.verb:
            continue
        info: ControllerInfo | None = None
        body_text = ""
        def_file, def_line = route.file, route.line
        method_name = route.method or ""
        ctor_auth = False
        if route.closure is not None:
            src = sources[route.closure_file]
            body_text = ast.text(route.closure, src)
            def_line = ast.line(route.closure, src)
            handler = f"closure@{route.uri or '/'}"
        else:
            handler = f"{route.cls}@{method_name}"
            for key in _resolve(route.cls or "", imports_by_file.get(route.file, {})):
                if key in controllers:
                    info = controllers[key]
                    break
            if info is None:
                unresolved.append(
                    Unresolved(
                        "laravel_controller",
                        route.file,
                        route.line,
                        f"controller {route.cls} not found in scanned files",
                    )
                )
            else:
                target = info.methods.get(method_name)
                if target is None:
                    unresolved.append(
                        Unresolved(
                            "laravel_controller",
                            route.file,
                            route.line,
                            f"{route.cls}::{method_name} not found",
                        )
                    )
                else:
                    node, src = target
                    body_text = ast.text(node, src)
                    def_file, def_line = info.file, ast.line(node, src)
                for name, only, except_ in info.ctor_middleware:
                    applies = (only is None or method_name in only) and (
                        except_ is None or method_name not in except_
                    )
                    if applies and AUTH_MIDDLEWARE.match(name.split(":")[0]):
                        ctor_auth = True
        middleware = [m for m in route.middleware if m not in route.without]
        auth_names = [m for m in middleware if AUTH_MIDDLEWARE.match(m.split(":")[0])]
        if auth_names:
            auth = AuthInfo(True, auth_names[0])
        elif ctor_auth:
            auth = AuthInfo(True, "controller middleware")
        elif INLINE_AUTH.search(body_text):
            auth = AuthInfo(None, "inline user check")
        else:
            auth = AuthInfo(False, "")
        traits: list[str] = []
        if WRITE.search(body_text):
            traits.append("writes")
        if READ.search(body_text):
            traits.append("reads-data")
        exempt = any(fnmatch.fnmatch(route.uri.strip("/"), p.strip("/")) for p in csrf_patterns)
        if (
            exempt
            or "VerifyCsrfToken" in "".join(route.without)
            or "ValidateCsrfToken" in "".join(route.without)
        ):
            traits.append("csrf-exempt")
        if route.file.endswith("api.php"):
            traits = [t for t in traits if t != "csrf-exempt"]  # the api group has no CSRF layer
        out.append(
            Entrypoint(
                kind="laravel-route",
                file=def_file,
                line=def_line,
                handler=handler,
                params=tuple(PARAM_RE.findall(route.uri)),
                auth=auth,
                route=f"{route.verb} /{route.uri}",
                route_file=route.file,
                route_line=route.line,
                traits=tuple(traits),
            )
        )
    return out
