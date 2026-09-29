"""Django plugin: detection, settings reader, models -> schema (WP-6.1)."""

from __future__ import annotations

from pathlib import Path

from vulnfab.core.loader import Repo
from vulnfab.core.models import Confidence
from vulnfab.plugins.django import DjangoPlugin
from vulnfab.plugins.django.pyconf import Dynamic, read_models, read_settings


def repo_with(tmp_path: Path, files: dict[str, str]) -> Repo:
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return Repo(tmp_path)


def test_detect_manage_py(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"manage.py": "import django\n"})
    assert DjangoPlugin().detect(repo) is Confidence.HIGH


def test_detect_settings_installed_apps(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"proj/settings.py": "INSTALLED_APPS = []\n"})
    assert DjangoPlugin().detect(repo) is Confidence.HIGH


def test_detect_requirements_only_is_medium(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"requirements.txt": "Django==4.2\nrequests\n"})
    assert DjangoPlugin().detect(repo) is Confidence.MEDIUM


def test_detect_unrelated_project(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"app.py": "print(1)\n", "requirements.txt": "flask\n"})
    assert DjangoPlugin().detect(repo) is Confidence.LOW


def test_settings_reader_literals_and_dynamic() -> None:
    text = (
        "import os\n"
        "DEBUG = True\n"
        "SECRET_KEY = os.environ['K']\n"
        "ALLOWED_HOSTS = ['a', 'b']\n"
        "MIDDLEWARE = ['x']\n"
        "MIDDLEWARE += ['y']\n"
        "if os.environ.get('P'):\n"
        "    SESSION_COOKIE_SECURE = True\n"
    )
    read = read_settings(text)
    assert read is not None
    assert read.values["DEBUG"] is True
    assert isinstance(read.values["SECRET_KEY"], Dynamic)
    assert read.values["ALLOWED_HOSTS"] == ["a", "b"]
    assert "MIDDLEWARE" in read.mutated
    assert "SESSION_COOKIE_SECURE" in read.conditional
    assert read.lines["DEBUG"] == 2


def test_settings_reader_rejects_python2() -> None:
    assert read_settings("print 'x'\n") is None


def test_models_reader_fields_and_relations() -> None:
    text = (
        "from django.db import models\n"
        "class Project(models.Model):\n"
        "    title = models.CharField(max_length=10, unique=True)\n"
        "    owner = models.ForeignKey('auth.User', null=True, on_delete=models.CASCADE)\n"
        "    class Meta:\n"
        "        ordering = ['title']\n"
        "class Base(models.Model):\n"
        "    class Meta:\n"
        "        abstract = True\n"
    )
    classes = read_models(text)
    assert classes is not None
    project, base = classes
    assert [f.name for f in project.fields] == ["title", "owner"]
    assert project.fields[0].unique and project.fields[1].null
    assert project.fields[1].target == "auth.User"
    assert base.abstract


def test_extract_schema_builds_tables_with_inheritance(tmp_path: Path) -> None:
    repo = repo_with(
        tmp_path,
        {
            "proj/settings.py": "DEBUG = True\nINSTALLED_APPS = []\n",
            "shop/models.py": (
                "from django.db import models\n"
                "class Stamped(models.Model):\n"
                "    created = models.DateTimeField()\n"
                "    class Meta:\n        abstract = True\n"
                "class Order(Stamped):\n"
                "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
                "    api_token = models.CharField(max_length=40)\n"
                "class Helper:\n    pass\n"
            ),
        },
    )
    model = DjangoPlugin().extract_schema(repo)
    assert model is not None
    assert list(model.tables) == ["shop.order"]
    order = model.tables["shop.order"]
    assert [c.name for c in order.columns] == ["created", "user", "api_token"]
    assert order.columns[1].references == "auth.User"
    assert order.columns[2].sensitive_hint and not order.columns[0].sensitive_hint
    assert model.configs["proj/settings.py"].data["DEBUG"] is True


def test_extract_schema_none_for_non_django(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"app.py": "x = 1\n"})
    assert DjangoPlugin().extract_schema(repo) is None


def _idor_finding(snippet: str):
    from vulnfab.core.models import Finding, Severity

    return Finding(
        rule_id="tpy-idor",
        title="t",
        cwe=(),
        owasp=None,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        tier="B",
        file="v.py",
        line=1,
        end_line=1,
        snippet=snippet,
        message="m",
    )


def test_refine_lowers_idor_on_models_without_owner(tmp_path: Path) -> None:
    repo = repo_with(
        tmp_path,
        {
            "manage.py": "import django\n",
            "shop/models.py": (
                "from django.db import models\n"
                "class Country(models.Model):\n    name = models.CharField(max_length=5)\n"
                "class Order(models.Model):\n"
                "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
            ),
        },
    )
    plugin = DjangoPlugin()
    model = plugin.extract_schema(repo)
    assert model is not None
    raw = [
        (_idor_finding("c = Country.objects.get(pk=pk)"), "s1"),
        (_idor_finding("o = get_object_or_404(Order, pk=pk)"), "s2"),
        (_idor_finding("x = unknown_call(pk)"), "s3"),
    ]
    out = plugin.refine(raw, model)
    assert [f.confidence for f, _ in out] == [Confidence.LOW, Confidence.MEDIUM, Confidence.MEDIUM]
    assert "reference data" in out[0][0].message


def test_refine_owner_relation_can_be_inherited_from_a_parent_model(tmp_path: Path) -> None:
    repo = repo_with(
        tmp_path,
        {
            "manage.py": "import django\n",
            "app/models.py": (
                "from django.db import models\n"
                "class Project(models.Model):\n"
                "    users_assigned = models.ManyToManyField('auth.User')\n"
                "class File(models.Model):\n"
                "    project = models.ForeignKey(Project, on_delete=models.CASCADE)\n"
                "class Loose(models.Model):\n    label = models.CharField(max_length=3)\n"
            ),
        },
    )
    plugin = DjangoPlugin()
    model = plugin.extract_schema(repo)
    assert model is not None
    raw = [
        (_idor_finding("f = File.objects.get(pk=pk)"), "a"),
        (_idor_finding("l = Loose.objects.get(pk=pk)"), "b"),
    ]
    out = plugin.refine(raw, model)
    assert [f.confidence for f, _ in out] == [Confidence.MEDIUM, Confidence.LOW]
