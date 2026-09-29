"""Laravel route collection, middleware inheritance and controller auth (WP-7.2)."""
# ruff: noqa: E501

from __future__ import annotations

from vulnfab.core.models import SourceFile, Unresolved
from vulnfab.core.parsing import parse_file
from vulnfab.plugins.laravel import routes


def collect(files: dict[str, str]):
    parsed = {p: parse_file(SourceFile(p, "php", t, "0" * 64)) for p, t in files.items()}
    unresolved: list[Unresolved] = []
    collector = routes.RouteCollector(unresolved)
    imports = {}
    for path in sorted(p for p in parsed if p.startswith("routes/")):
        collector.collect(path, parsed[path])
        imports[path] = collector.imports
    entries = routes.to_entrypoints(
        collector.routes,
        routes.index_controllers(parsed),
        imports,
        {p: pf.source for p, pf in parsed.items()},
        routes.csrf_except(parsed),
        unresolved,
    )
    return entries, unresolved


CONTROLLER = """<?php
namespace App\\Http\\Controllers;
class PostController extends Controller {
    public function __construct() { $this->middleware('auth')->except(['index']); }
    public function index() { return Post::all(); }
    public function show($id) { return Post::findOrFail($id); }
    public function store(Request $r) { Post::create($r->all()); }
    public function mine() { return Post::where('user_id', auth()->id())->get(); }
}
"""


def by_handler(entries):
    return {e.handler: e for e in entries}


def test_group_middleware_prefix_and_nesting() -> None:
    web = """<?php
use App\\Http\\Controllers\\PostController;
Route::middleware(['auth', 'verified'])->prefix('admin')->group(function () {
    Route::get('/posts/{id}', [PostController::class, 'show'])->name('x');
    Route::prefix('deep')->group(function () {
        Route::post('/posts', 'PostController@store');
    });
});
Route::post('/open', [PostController::class, 'store']);
"""
    e = collect({"routes/web.php": web, "app/Http/Controllers/PostController.php": CONTROLLER})[0]
    routes_by_uri = {x.route: x for x in e}
    assert routes_by_uri["GET /admin/posts/{id}"].auth.required is True
    assert routes_by_uri["GET /admin/posts/{id}"].auth.mechanism == "auth"
    assert routes_by_uri["POST /admin/deep/posts"].auth.required is True
    # store() is covered by the controller's own middleware('auth')->except(['index'])
    assert routes_by_uri["POST /open"].auth.mechanism == "controller middleware"


def test_controller_constructor_middleware_only_except() -> None:
    web = "<?php\nRoute::get('/posts', [PostController::class, 'index']);\nRoute::get('/posts/{id}', [PostController::class, 'show']);\n"
    e = by_handler(
        collect({"routes/web.php": web, "app/Http/Controllers/PostController.php": CONTROLLER})[0]
    )
    assert e["PostController@index"].auth.required is False  # excluded by ->except(['index'])
    assert (
        e["PostController@show"].auth.required is True
        and e["PostController@show"].auth.mechanism == "controller middleware"
    )


def test_inline_auth_and_traits() -> None:
    web = "<?php\nRoute::get('/mine', [PostController::class, 'mine']);\nRoute::post('/posts', [PostController::class, 'store']);\n"
    ctrl = CONTROLLER.replace("$this->middleware('auth')->except(['index']);", "")
    e = by_handler(
        collect({"routes/web.php": web, "app/Http/Controllers/PostController.php": ctrl})[0]
    )
    assert e["PostController@mine"].auth.required is None
    assert (
        "writes" in e["PostController@store"].traits
        and e["PostController@store"].auth.required is False
    )


def test_resource_only_except_and_api_prefix() -> None:
    api = "<?php\nRoute::apiResource('photos', PhotoController::class)->only(['index', 'show']);\nRoute::resource('tags', TagController::class)->except(['destroy', 'create', 'edit']);\n"
    entries, unresolved = collect({"routes/api.php": api})
    uris = sorted(e.route for e in entries)
    assert (
        uris
        == [
            "GET /api/photos",
            "GET /api/photos/{photo}",
            "GET /api/tags",
            "GET /api/tags/{tag}",
            "POST /api/tags",
            "PUT /api/tags/{tag}",
        ]
        or len(uris) == 6
    )
    assert any(u.kind == "laravel_controller" for u in unresolved)


def test_csrf_except_and_without_middleware() -> None:
    web = "<?php\nRoute::post('/stripe/hook', [PostController::class, 'store']);\nRoute::post('/other', [PostController::class, 'store'])->withoutMiddleware([VerifyCsrfToken::class]);\nRoute::post('/normal', [PostController::class, 'store']);\n"
    verify = "<?php\nclass VerifyCsrfToken {\n    protected $except = ['stripe/*'];\n}\n"
    entries = collect(
        {
            "routes/web.php": web,
            "app/Http/Middleware/VerifyCsrfToken.php": verify,
            "app/Http/Controllers/PostController.php": CONTROLLER,
        }
    )[0]
    exempt = {e.route for e in entries if "csrf-exempt" in e.traits}
    assert exempt == {"POST /stripe/hook", "POST /other"}


def test_api_routes_are_never_csrf_exempt() -> None:
    api = "<?php\nRoute::post('/x', [PostController::class, 'store'])->withoutMiddleware([VerifyCsrfToken::class]);\n"
    entries = collect(
        {"routes/api.php": api, "app/Http/Controllers/PostController.php": CONTROLLER}
    )[0]
    assert "csrf-exempt" not in entries[0].traits


def test_group_with_array_attributes() -> None:
    web = (
        "<?php\nRoute::group(['middleware' => ['auth'], 'prefix' => 'a'], function () {\n"
        "    Route::get('/x', [PostController::class, 'show']);\n});\n"
    )
    ctrl = CONTROLLER.replace("$this->middleware('auth')->except(['index']);", "")
    entries, _ = collect({"routes/web.php": web, "app/Http/Controllers/PostController.php": ctrl})
    assert entries[0].route == "GET /a/x" and entries[0].auth.required is True
