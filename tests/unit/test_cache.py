"""Result cache: identical results, real speed-up, correct invalidation (WP-10.4)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from vulnfab.core import cache
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence
from vulnfab.core.report import to_json_dict


def make_repo(root: Path) -> None:
    (root / "manage.py").write_text("import django\n")
    (root / "proj").mkdir()
    (root / "proj/settings.py").write_text("DEBUG = True\nINSTALLED_APPS = []\n")
    (root / "proj/views.py").write_text(
        "import os\n\ndef v(request):\n    os.system('ls ' + request.GET['d'])\n"
    )
    (root / "app.py").write_text("eval(input())\n")


def opts(**kw) -> ScanOptions:  # type: ignore[no-untyped-def]
    return ScanOptions(min_confidence=Confidence.LOW, use_cache=True, **kw)


def dump(result) -> str:  # type: ignore[no-untyped-def]
    return json.dumps(to_json_dict(result), sort_keys=True)


def test_cached_result_is_identical(tmp_path: Path) -> None:
    make_repo(tmp_path)
    fresh = scan(tmp_path, ScanOptions(min_confidence=Confidence.LOW, use_cache=False))
    first = scan(tmp_path, opts())
    second = scan(tmp_path, opts())
    assert dump(fresh) == dump(first) == dump(second)
    assert len(list(cache.cache_dir().rglob("*.json"))) == 1


def test_cache_hit_is_much_faster(tmp_path: Path) -> None:
    make_repo(tmp_path)
    for i in range(60):  # enough parse/analysis work for the difference to be visible
        (tmp_path / f"m{i}.py").write_text(
            "import os\n" + "def f(x):\n    return os.system(x)\n" * 30
        )
    start = time.perf_counter()
    scan(tmp_path, opts())
    cold = time.perf_counter() - start
    start = time.perf_counter()
    scan(tmp_path, opts())
    warm = time.perf_counter() - start
    assert warm * 5 <= cold, (cold, warm)


def test_changing_a_file_invalidates(tmp_path: Path) -> None:
    make_repo(tmp_path)
    before = scan(tmp_path, opts())
    (tmp_path / "app.py").write_text("x = 1\n")
    after = scan(tmp_path, opts())
    assert len(after.findings) < len(before.findings)


def test_options_applied_after_cache_still_work(tmp_path: Path) -> None:
    make_repo(tmp_path)
    scan(tmp_path, opts())
    high_only = scan(tmp_path, ScanOptions(min_confidence=Confidence.HIGH, use_cache=True))
    everything = scan(tmp_path, opts())
    assert len(high_only.findings) < len(everything.findings)
    assert high_only.coverage.hidden_low_confidence > 0


def test_config_change_invalidates(tmp_path: Path) -> None:
    make_repo(tmp_path)
    before = scan(tmp_path, opts())
    (tmp_path / ".vulnfab.yml").write_text("disable_rules: [py-eval, tpy-codei]\n")
    after = scan(tmp_path, opts())
    assert {f.rule_id for f in after.findings} < {f.rule_id for f in before.findings}


def test_corrupt_cache_entry_is_ignored(tmp_path: Path) -> None:
    make_repo(tmp_path)
    scan(tmp_path, opts())
    for entry in cache.cache_dir().rglob("*.json"):
        entry.write_text("{not json")
    assert scan(tmp_path, opts()).findings


def test_cache_prunes_old_entries(tmp_path: Path) -> None:
    make_repo(tmp_path)
    for i in range(cache.KEEP_PER_TARGET + 3):
        (tmp_path / "app.py").write_text(f"x = {i}\n")
        scan(tmp_path, opts())
    assert len(list(cache.cache_dir().rglob("*.json"))) == cache.KEEP_PER_TARGET
