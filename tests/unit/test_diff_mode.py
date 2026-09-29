"""--since: only findings affected by the change are reported (WP-10.3)."""
# ruff: noqa: E501

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.gitdiff import GitError, affected_files, changed_files, import_graph
from vulnfab.core.models import Confidence
from vulnfab.core.rules import RuleLoadError

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
    )


def write(root: Path, rel: str, text: str) -> None:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/util.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    write(
        tmp_path,
        "pkg/views.py",
        "from pkg.util import run\n\ndef v(request):\n    run(request.GET['a'])\n",
    )
    write(
        tmp_path,
        "pkg/other.py",
        "import os\n\ndef o(request):\n    os.system('x' + request.GET['b'])\n",
    )
    write(tmp_path, "pkg/clean.py", "def c():\n    return 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def files_of(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.file for f in result.findings}


def opts(**kw) -> ScanOptions:  # type: ignore[no-untyped-def]
    return ScanOptions(min_confidence=Confidence.LOW, **kw)


def test_no_change_reports_nothing(repo: Path) -> None:
    assert not scan(repo, opts(since="HEAD")).findings


def test_change_reports_the_file_and_its_dependents_only(repo: Path) -> None:
    write(repo, "pkg/util.py", "import os\n\ndef run(cmd):\n    os.system('ls ' + cmd)\n")
    full = scan(repo, opts())
    diff = scan(repo, opts(since="HEAD"))
    assert "pkg/other.py" in files_of(full)  # exists in the full scan...
    assert "pkg/other.py" not in files_of(diff)  # ...but is not affected by the change
    assert {"pkg/util.py"} <= files_of(diff)
    assert files_of(diff) <= files_of(full)


def test_diff_findings_equal_full_findings_restricted_to_scope(repo: Path) -> None:
    write(
        repo,
        "pkg/views.py",
        "from pkg.util import run\n\ndef v(request):\n    run(request.GET['z'])\n",
    )
    write(repo, "pkg/new.py", "import os\n\ndef n(request):\n    os.system(request.GET['n'])\n")
    full = scan(repo, opts())
    diff = scan(repo, opts(since="HEAD"))
    changed = changed_files(repo, "HEAD")
    assert changed == {"pkg/views.py", "pkg/new.py"}
    texts = {
        p: ("python", (repo / p).read_text())
        for p in [
            "pkg/util.py",
            "pkg/views.py",
            "pkg/other.py",
            "pkg/clean.py",
            "pkg/new.py",
            "pkg/__init__.py",
        ]
    }
    affected, everything = affected_files(changed, texts)
    assert not everything and affected == {"pkg/views.py", "pkg/new.py"}
    expected = {
        f.fingerprint
        for f in full.findings
        if f.file in affected or any(s.file in changed for s in f.trace)
    }
    assert {f.fingerprint for f in diff.findings} == expected
    # the taint flow crosses a changed file (views.py -> util.py): the sink in util.py is in scope
    assert "pkg/util.py" in files_of(diff)


def test_settings_change_widens_scope_to_everything(repo: Path) -> None:
    write(repo, "manage.py", "import django\n")
    write(repo, "proj/settings.py", "DEBUG = True\nINSTALLED_APPS = []\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "django")
    write(repo, "proj/settings.py", "DEBUG = False\nINSTALLED_APPS = []\n")
    diff = scan(repo, opts(since="HEAD"))
    assert "pkg/other.py" in files_of(diff)  # global file changed: nothing is excluded


def test_bad_ref_and_non_repo_are_reported(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    with pytest.raises(RuleLoadError):
        scan(repo, opts(since="no-such-ref"))
    outside = tmp_path_factory.mktemp("plain")
    write(outside, "a.py", "x = 1\n")
    with pytest.raises(GitError):
        changed_files(outside, "HEAD")


def test_import_graph_resolves_python_js_php() -> None:
    graph = import_graph(
        {
            "a/x.py": ("python", "from a import y\nimport a.z\n"),
            "a/y.py": ("python", ""),
            "a/z.py": ("python", ""),
            "web/app.ts": (
                "typescript",
                "import { q } from './lib'; const r = require('./other');",
            ),
            "web/lib.ts": ("typescript", ""),
            "web/other.js": ("javascript", ""),
            "app/Foo.php": ("php", "<?php class Foo {}"),
            "app/Bar.php": ("php", "<?php use App\\Foo; class Bar extends Foo {}"),
        }
    )
    assert graph["a/x.py"] == {"a/y.py", "a/z.py"}
    assert graph["web/app.ts"] == {"web/lib.ts", "web/other.js"}
    assert graph["app/Bar.php"] == {"app/Foo.php"}
