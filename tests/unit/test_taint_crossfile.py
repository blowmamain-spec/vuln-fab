"""Inter-file taint (WP-5.5): import resolution and cross-module summaries."""
# ruff: noqa: E501

from __future__ import annotations

from vulnfab.core.lower import lower_file
from vulnfab.core.models import SourceFile
from vulnfab.core.modindex import ModuleIndex
from vulnfab.core.parsing import parse_file
from vulnfab.core.taint import ProjectAnalysis
from vulnfab.core.taintspec import TaintSpec

PY = TaintSpec.from_rule(["field request.args"], ["call os.system"], ["call int"], [])
JS = TaintSpec.from_rule(["field req.query"], ["call db.query arg0", "call eval"], [], [])
LANG = {"py": "python", "js": "javascript", "ts": "typescript"}


def project(files: dict[str, str], spec: TaintSpec):
    mods = []
    for path, code in files.items():
        lang = LANG[path.rsplit(".", 1)[1]]
        mods.append(lower_file(parse_file(SourceFile(path, lang, code, "0" * 64))))
    return ProjectAnalysis(mods, spec).run()


def test_python_from_import_function() -> None:
    hits = project(
        {
            "app/util.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
            "app/views.py": "from app.util import run\n\ndef view():\n    run(request.args['c'])\n",
        },
        PY,
    )
    assert [(h.file, h.line) for h in hits] == [("app/util.py", 4)]
    assert {s.file for s in hits[0].trace} == {"app/views.py", "app/util.py"}


def test_python_module_import_and_alias() -> None:
    files = {
        "pkg/helpers.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n\ndef ident(x):\n    return x\n",
        "pkg/a.py": "import pkg.helpers\n\ndef v():\n    pkg.helpers.run(request.args['c'])\n",
        "pkg/b.py": "from pkg import helpers as h\nfrom pkg.helpers import ident\nimport os\n\ndef v():\n    os.system(ident(request.args['c']))\n",
    }
    hits = project(files, PY)
    assert sorted((h.file, h.line) for h in hits) == [("pkg/b.py", 6), ("pkg/helpers.py", 4)]


def test_python_relative_import() -> None:
    hits = project(
        {
            "pkg/util.py": "import os\n\ndef run(c):\n    os.system(c)\n",
            "pkg/views.py": "from .util import run\n\ndef v():\n    run(request.args['c'])\n",
        },
        PY,
    )
    assert [(h.file, h.line) for h in hits] == [("pkg/util.py", 4)]


def test_python_sanitizer_in_other_file() -> None:
    hits = project(
        {
            "a/util.py": "import os\n\ndef run(c):\n    os.system(str(int(c)))\n",
            "a/views.py": "from a.util import run\n\ndef v():\n    run(request.args['c'])\n",
        },
        PY,
    )
    assert hits == []


def test_python_unresolved_import_is_not_a_hit() -> None:
    assert not project(
        {"a/views.py": "from thirdparty import run\n\ndef v():\n    run(request.args['c'])\n"}, PY
    )


def test_python_return_across_files() -> None:
    hits = project(
        {
            "a/src.py": "def get():\n    return request.args['x']\n",
            "a/views.py": "import os\nfrom a.src import get\n\ndef v():\n    os.system(get())\n",
        },
        PY,
    )
    assert [(h.file, h.line) for h in hits] == [("a/views.py", 5)]


def test_es_named_and_relative_imports() -> None:
    hits = project(
        {
            "src/db.ts": "export function q(sql: string) { db.query(sql); }\n",
            "src/routes/r.ts": "import { q } from '../db';\nexport function h(req: any) { q(req.query.id); }\n",
        },
        JS,
    )
    assert [(h.file, h.line) for h in hits] == [("src/db.ts", 1)]


def test_commonjs_require_destructured_and_namespace() -> None:
    hits = project(
        {
            "lib/db.js": "function run(s) { db.query(s); }\nmodule.exports = { run };\n",
            "routes/a.js": "const { run } = require('../lib/db');\nfunction h(req) { run(req.query.a); }\n",
            "routes/b.js": "const d = require('../lib/db');\nfunction h(req) { d.run(req.query.b); }\n",
        },
        JS,
    )
    assert {(h.file, h.line) for h in hits} == {("lib/db.js", 1)}
    assert len(hits) == 1


def test_commonjs_exports_assignment() -> None:
    hits = project(
        {
            "lib/x.js": "exports.go = function (s) { eval(s); };\n",
            "routes/a.js": "const x = require('../lib/x');\nfunction h(req) { x.go(req.query.a); }\n",
        },
        JS,
    )
    assert [(h.file, h.line) for h in hits] == [("lib/x.js", 1)]


def test_import_cycle_terminates() -> None:
    hits = project(
        {
            "a/x.py": "from a.y import g\n\ndef f(v):\n    return g(v)\n",
            "a/y.py": "from a.x import f\nimport os\n\ndef g(v):\n    os.system(v)\n    return f(v)\n",
            "a/z.py": "from a.x import f\n\ndef h():\n    f(request.args['q'])\n",
        },
        PY,
    )
    assert [(h.file, h.line) for h in hits] == [("a/y.py", 5)]


def test_module_index_resolution() -> None:
    idx = ModuleIndex(
        {
            "src/a/index.ts": "typescript",
            "src/b.ts": "typescript",
            "src/c.ts": "typescript",
            "src/a/x.ts": "typescript",
            "pkg/x.py": "python",
            "pkg/m.py": "python",
            "pkg/sub/__init__.py": "python",
        }
    )
    assert idx.resolve("src/c.ts", "./a") == "src/a/index.ts"
    assert idx.resolve("src/a/x.ts", "../b") == "src/b.ts"
    assert idx.resolve("src/c.ts", "@/b") == "src/b.ts"
    assert idx.resolve("src/c.ts", "express") is None
    assert idx.resolve("pkg/x.py", "pkg.sub") == "pkg/sub/__init__.py"
    assert idx.resolve("pkg/x.py", ".m") == "pkg/m.py"
    assert idx.resolve("pkg/x.py", "os") is None
