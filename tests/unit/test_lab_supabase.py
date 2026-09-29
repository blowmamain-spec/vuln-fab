"""Sanity checks for the supabase-vuln lab and its ground truth (WP-0.5)."""

from __future__ import annotations

import importlib.util
import json
import tomllib
from pathlib import Path

import pytest
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from vulnfab.core.sqlparser import PglastParser

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "benchmarks" / "labs" / "supabase-vuln"
TRUTH = ROOT / "benchmarks" / "truth" / "supabase-vuln.json"

# Every class here must have at least one vulnerable label and one decoy.
REQUIRED_CLASSES = {
    # Supabase / Postgres
    "rls-missing",
    "policy-true",
    "policy-anon-write",
    "policy-user-metadata",
    "policy-no-uid",
    "definer-no-path",
    "view-no-invoker",
    "grant-broad",
    "default-priv",
    "dynamic-sql",
    "storage-public",
    "storage-policy",
    "seed-secret",
    "config-signup",
    # TypeScript
    "service-role-client",
    "secret-hardcoded",
    "xss-dangerous-html",
    "cmd-injection",
    "dynamic-eval",
    "supabase-or-inject",
    "edge-no-jwt",
    "table-no-rls",
    "idor-eq-id",
}


def _load_truth_module():  # type: ignore[no-untyped-def]
    path = ROOT / "benchmarks" / "labs" / "truth_from_markers.py"
    spec = importlib.util.spec_from_file_location("truth_from_markers", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _has_error(node: Node) -> bool:
    return node.has_error


def test_sql_files_parse_without_issues() -> None:
    parser = PglastParser()
    files = sorted(LAB.rglob("*.sql"))
    assert files
    for path in files:
        result = parser.parse_lenient(path.read_text())
        assert result.issues == [], f"{path.name}: {result.issues}"
        assert result.statements


def test_toml_is_valid() -> None:
    data = tomllib.loads((LAB / "supabase" / "config.toml").read_text())
    assert data["functions"]["legacy-hook"]["verify_jwt"] is False
    assert data["functions"]["process-order"]["verify_jwt"] is True


@pytest.mark.parametrize("suffix", [".ts", ".tsx"])
def test_typescript_files_have_no_syntax_errors(suffix: str) -> None:
    language = Language(tsts.language_tsx() if suffix == ".tsx" else tsts.language_typescript())
    parser = Parser(language)
    files = sorted(LAB.rglob(f"*{suffix}"))
    assert files
    for path in files:
        tree = parser.parse(path.read_bytes())
        assert not _has_error(tree.root_node), f"syntax error in {path.relative_to(LAB)}"


def test_truth_file_matches_markers() -> None:
    module = _load_truth_module()
    expected = json.dumps(module.build("supabase-vuln"), indent=2, ensure_ascii=False) + "\n"
    assert TRUTH.read_text() == expected, (
        "run: python benchmarks/labs/truth_from_markers.py supabase-vuln"
    )


def test_every_required_class_has_vulnerable_and_decoy() -> None:
    items = json.loads(TRUTH.read_text())["items"]
    kinds: dict[str, set[str]] = {}
    for item in items:
        kinds.setdefault(item["class"], set()).add(item["kind"])
    missing = {
        c: kinds.get(c, set()) for c in REQUIRED_CLASSES if kinds.get(c) != {"vulnerable", "decoy"}
    }
    assert missing == {}


def test_truth_ranges_are_valid() -> None:
    items = json.loads(TRUTH.read_text())["items"]
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids))
    for item in items:
        lines = (LAB / item["file"]).read_text().split("\n")
        assert 1 <= item["line_start"] <= item["line_end"] <= len(lines)
        assert item["kind"] in {"vulnerable", "decoy"}
        assert item["tier"] in {None, "A", "B", "C"}
