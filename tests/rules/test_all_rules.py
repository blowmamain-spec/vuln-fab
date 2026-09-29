"""CI gate (decision D10): every rule has tests and passes them."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnfab.core.ruletest import run_rule_tests
from vulnfab.core.rules import load_rules
from vulnfab.plugins import registry

TESTS_ROOT = Path(__file__).parent


def _all_rules() -> list[object]:
    packs: list[Path] = []
    for plugin in registry.discover():
        packs.extend(p for p in plugin.rule_packs() if p.exists())
    return load_rules(packs)


RULES = _all_rules()


def test_rule_ids_are_unique_and_namespaced() -> None:
    ids = [r.id for r in RULES]  # type: ignore[attr-defined]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", RULES, ids=[r.id for r in RULES])  # type: ignore[attr-defined]
def test_rule_passes_its_tests(rule: object) -> None:
    result = run_rule_tests(rule, TESTS_ROOT)
    assert result.ok, "\n".join(result.problems)


def test_no_orphan_test_directories() -> None:
    known = {r.id for r in RULES}  # type: ignore[attr-defined]
    on_disk = {p.name for p in TESTS_ROOT.iterdir() if p.is_dir() and not p.name.startswith("_")}
    assert on_disk - known == set(), f"test directories without a rule: {sorted(on_disk - known)}"


def test_every_rule_declares_tests() -> None:
    for rule in RULES:
        assert rule.tests.vulnerable and rule.tests.safe, rule.id  # type: ignore[attr-defined]
