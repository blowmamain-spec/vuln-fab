"""URL configuration resolution and view authentication (WP-6.2)."""
# ruff: noqa: E501

from __future__ import annotations

from vulnfab.plugins.django import urlconf


def resolve(files: dict[str, str], *, drf: bool = False, middleware: bool = False):
    index = urlconf.build_index(files)
    resolver = urlconf.ViewResolver(index, drf_default_auth=drf, login_middleware=middleware)
    included = set()
    modules = index.url_modules()
    for m in modules:
        imports = urlconf._imports(m, index)
        for r in urlconf._collect_routes(m):
            if r.include is not None:
                child = urlconf._resolve_include(r, index, imports)
                if child:
                    included.add(child.path)
    roots = [m for m in modules if m.path not in included] or modules
    return urlconf.walk_urls(index, roots, resolver)


def by_handler(routes):
    return {r.view.qualname: r for r in routes if r.view}


def test_nested_include_and_prefix_and_params() -> None:
    routes = resolve(
        {
            "proj/urls.py": (
                "from django.urls import path, include\n"
                "urlpatterns = [path('shop/', include('shop.urls'))]\n"
            ),
            "shop/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [path('item/<int:pk>/', views.item)]\n"
            ),
            "shop/views.py": "def item(request, pk):\n    return None\n",
        }
    )
    r = by_handler(routes)["item"]
    assert r.route == "shop/item/<int:pk>/"
    assert r.params == ("pk",)
    assert r.view.file == "shop/views.py" and r.view.line == 1


def test_string_views_patterns_and_regex_groups() -> None:
    routes = resolve(
        {
            "app/urls.py": (
                "from django.conf.urls import patterns, url\n"
                "urlpatterns = patterns('', url(r'^a/(?P<pid>\\d+)/$', 'app.views.a'))\n"
            ),
            "app/views.py": "def a(request, pid):\n    return None\n",
        }
    )
    assert by_handler(routes)["a"].params == ("pid",)


def test_decorators_mixins_and_inline_checks() -> None:
    views = (
        "from django.contrib.auth.decorators import login_required, permission_required\n"
        "from django.contrib.auth.mixins import LoginRequiredMixin\n"
        "from django.utils.decorators import method_decorator\n"
        "@login_required\n"
        "def a(request):\n    return None\n"
        "@permission_required('x.y')\n"
        "def b(request):\n    return None\n"
        "def c(request):\n    if not request.user.is_authenticated:\n        return None\n"
        "def d(request):\n    return None\n"
        "class E(LoginRequiredMixin, View):\n    pass\n"
        "@method_decorator(login_required, name='dispatch')\n"
        "class F(View):\n    pass\n"
    )
    urls = (
        "from django.urls import path\nfrom . import views as v\n"
        "urlpatterns = [path('a', v.a), path('b', v.b), path('c', v.c), path('d', v.d),"
        " path('e', v.E.as_view()), path('f', v.F.as_view())]\n"
    )
    routes = by_handler(resolve({"x/urls.py": urls, "x/views.py": views}))
    required = {k: r.view.auth.required for k, r in routes.items()}
    assert required == {"a": True, "b": True, "c": None, "d": False, "E": True, "F": True}


def test_drf_permission_classes_and_defaults() -> None:
    views = (
        "from rest_framework.views import APIView\n"
        "from rest_framework.decorators import api_view, permission_classes\n"
        "class Open(APIView):\n    permission_classes = [AllowAny]\n"
        "class Closed(APIView):\n    permission_classes = [IsAuthenticated]\n"
        "class Default(APIView):\n    pass\n"
        "@api_view(['GET'])\n@permission_classes([IsAuthenticated])\ndef fn(request):\n    return None\n"
    )
    urls = (
        "from django.urls import path\nfrom . import views\n"
        "urlpatterns = [path('o', views.Open.as_view()), path('c', views.Closed.as_view()),"
        " path('d', views.Default.as_view()), path('f', views.fn)]\n"
    )
    files = {"api/urls.py": urls, "api/views.py": views}
    plain = {k: r.view.auth.required for k, r in by_handler(resolve(files)).items()}
    assert plain == {"Open": False, "Closed": True, "Default": False, "fn": True}
    with_default = {
        k: r.view.auth.required for k, r in by_handler(resolve(files, drf=True)).items()
    }
    assert with_default["Default"] is True and with_default["Open"] is False


def test_login_required_middleware_covers_all_views() -> None:
    files = {
        "a/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('x', views.x)]\n",
        "a/views.py": "def x(request):\n    return None\n",
    }
    assert by_handler(resolve(files, middleware=True))["x"].view.auth.required is True


def test_traits_writes_and_reads() -> None:
    views = (
        "def w(request, pk):\n    Thing.objects.get(pk=pk).delete()\n"
        "def r(request, pk):\n    return Thing.objects.get(pk=pk)\n"
        "def n(request):\n    return None\n"
    )
    urls = (
        "from django.urls import path\nfrom . import views\n"
        "urlpatterns = [path('w/<int:pk>', views.w), path('r/<int:pk>', views.r), path('n', views.n)]\n"
    )
    routes = by_handler(resolve({"t/urls.py": urls, "t/views.py": views}))
    assert "writes" in routes["w"].view.traits
    assert routes["r"].view.traits == ("reads-data",)
    assert routes["n"].view.traits == ()


def test_unresolvable_view_is_reported_not_crashing() -> None:
    routes = resolve(
        {"z/urls.py": "from django.urls import path\nurlpatterns = [path('x', make_view())]\n"}
    )
    assert routes[0].view is None and routes[0].unresolved
