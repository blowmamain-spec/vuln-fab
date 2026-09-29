"""Parallel analysis must give byte-identical results to the serial run (WP-10.4)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence
from vulnfab.core.parallel import pmap
from vulnfab.core.report import to_json_dict


def _square(x: int, shared: dict[str, int]) -> int:
    return x * x + shared["offset"]


def test_pmap_preserves_order_and_passes_shared_state() -> None:
    items = list(range(10))
    assert pmap(_square, items, 3, {"offset": 1}) == [i * i + 1 for i in items]
    assert pmap(_square, items, 1, {"offset": 1}) == [i * i + 1 for i in items]
    assert pmap(_square, [], 4, {"offset": 0}) == []
    assert pmap(_square, [5], 4, {"offset": 0}) == [25]


def make_repo(root: Path) -> None:
    (root / "manage.py").write_text("import django\n")
    (root / "proj").mkdir()
    (root / "proj/settings.py").write_text("DEBUG = True\nSECRET_KEY = 'x'\nINSTALLED_APPS = []\n")
    for i in range(12):
        (root / f"proj/v{i}.py").write_text(
            "import os\nfrom proj.util import run\n"
            f"def view{i}(request):\n    run(request.GET['a'])\n"
            "    os.system('ls ' + request.GET['b'])\n"
        )
    (root / "proj/util.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    (root / "app.js").write_text("function h(req, db){ db.query('a' + req.query.id); }\n")


def test_jobs_do_not_change_results(tmp_path: Path) -> None:
    make_repo(tmp_path)
    opts = dict(min_confidence=Confidence.LOW, use_cache=False)
    serial = scan(tmp_path, ScanOptions(jobs=1, **opts))  # type: ignore[arg-type]
    parallel = scan(tmp_path, ScanOptions(jobs=3, **opts))  # type: ignore[arg-type]
    assert serial.findings
    assert json.dumps(to_json_dict(serial), sort_keys=True) == json.dumps(
        to_json_dict(parallel), sort_keys=True
    )
