"""Opt-in git-history secret scan (WP-8.3)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan

# random-looking fake value assembled at runtime so no secret-shaped literal sits in the repo
FAKE = "AKIA" + "QZ7XW3PLM9TR2VBN"


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True,
        capture_output=True,
    )


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "cfg.py").write_text(f"KEY = '{FAKE}'\n")
    (repo / "kept.py").write_text("NAME = 'x'\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add")
    (repo / "cfg.py").write_text("import os\nKEY = os.environ['KEY']\n")
    git(repo, "commit", "-qam", "remove")
    return repo


def test_removed_secret_found_only_with_history(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    plain = scan(repo, ScanOptions())
    assert not [f for f in plain.findings if f.rule_id == "sec-secret-history"]
    result = scan(repo, ScanOptions(history=True))
    hist = [f for f in result.findings if f.rule_id == "sec-secret-history"]
    assert len(hist) == 1 and hist[0].file == "cfg.py"
    assert FAKE not in hist[0].snippet and FAKE not in hist[0].message


def test_secret_still_in_tree_is_not_duplicated(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "cfg.py").write_text(f"KEY = '{FAKE}'\n")
    git(repo, "commit", "-qam", "readd")
    result = scan(repo, ScanOptions(history=True))
    assert not [f for f in result.findings if f.rule_id == "sec-secret-history"]


def test_history_limit_note_and_non_git(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    result = scan(repo, ScanOptions(history=True, history_limit=1))
    assert any("only the newest 1 of 2" in a for a in result.coverage.assumptions)
    plain = tmp_path / "nogit"
    plain.mkdir()
    (plain / "a.py").write_text("x = 1\n")
    result = scan(plain, ScanOptions(history=True))
    assert any("history was NOT scanned" in a for a in result.coverage.assumptions)
