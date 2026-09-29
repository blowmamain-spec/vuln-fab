"""Generated rule reference stays in sync; `vulnfab explain` works (WP-10.6)."""
# ruff: noqa: E501

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from vulnfab.cli import app

ROOT = Path(__file__).resolve().parents[2]


def test_rule_reference_is_in_sync_with_rule_packs() -> None:
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts/gen_rule_docs.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def test_explain_known_and_unknown_rule() -> None:
    runner = CliRunner()
    ok = runner.invoke(app, ["explain", "tpy-sqli"])
    assert ok.exit_code == 0 and "how to fix" in ok.output and "sources:" in ok.output
    bad = runner.invoke(app, ["explain", "tpy-nope"])
    assert bad.exit_code == 2 and "no rule" in bad.output


def test_doc_links_resolve() -> None:
    """Relative markdown links in README and docs point at files that exist."""
    broken: list[str] = []
    for md in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        for target in re.findall(
            r"\]\((?!https?://|#|mailto:)([^)#\s]+)", md.read_text(encoding="utf-8")
        ):
            if not (md.parent / target).exists():
                broken.append(f"{md.relative_to(ROOT)} -> {target}")
    assert broken == []
