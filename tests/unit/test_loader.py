import os
from pathlib import Path

from vulnfab.core.loader import IgnoreMatcher, Repo, detect_language


def _write(root: Path, rel: str, text: str | bytes = "x") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text)


def test_detect_language() -> None:
    assert detect_language("a/b.py") == "python"
    assert detect_language("web/x.tsx") == "tsx"
    assert detect_language("views/a.blade.php") == "blade"
    assert detect_language("app/Models/User.php") == "php"
    assert detect_language(".env.local") == "env"
    assert detect_language("Dockerfile") == "dockerfile"
    assert detect_language("supabase/config.toml") == "toml"
    assert detect_language("README.md") is None
    assert detect_language("LICENSE") is None


def test_ignore_matcher_semantics() -> None:
    m = IgnoreMatcher(["# c", "*.log", "/build", "docs/", "src/**/gen", "!keep.log", "a/*.tmp"])
    assert m.is_ignored("x.log", False)
    assert m.is_ignored("deep/dir/x.log", False)
    assert not m.is_ignored("keep.log", False)
    assert m.is_ignored("build", True)
    assert not m.is_ignored("sub/build", True)  # anchored
    assert m.is_ignored("docs", True)
    assert not m.is_ignored("docs", False)  # dir-only
    assert m.is_ignored("src/a/b/gen", True)
    assert m.is_ignored("src/gen", True)
    assert m.is_ignored("a/x.tmp", False)
    assert not m.is_ignored("a/b/x.tmp", False)


def test_walk_ignores_defaults_and_patterns(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "print(1)")
    _write(tmp_path, "node_modules/lib/index.js")
    _write(tmp_path, "vendor/pkg/a.php")
    _write(tmp_path, ".git/config")
    _write(tmp_path, "gen/out.py")
    _write(tmp_path, "src/keep.ts", "let a = 1")
    _write(tmp_path, ".vulnfabignore", "gen/\n")
    repo = Repo(tmp_path)
    assert repo.paths == [".vulnfabignore", "app.py", "src/keep.ts"]
    assert repo.ignored_count == 4  # node_modules, vendor, .git, gen


def test_load_hashes_and_classifies(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "print(1)\n")
    _write(tmp_path, "notes.md", "hi")
    _write(tmp_path, "big.py", "x = 1\n" * 1000)
    _write(tmp_path, "blob.py", b"\x00\x01\x02binary")
    _write(tmp_path, "bom.php", b"\xef\xbb\xbf<?php echo 1;")
    repo = Repo(tmp_path, max_file_bytes=1000)
    result = repo.load()
    by_path = {f.path: f for f in result.files}
    assert set(by_path) == {"a.py", "bom.php"}
    assert by_path["a.py"].language == "python"
    assert len(by_path["a.py"].sha256) == 64
    assert by_path["bom.php"].text.startswith("<?php")
    reasons = {s.file: s.reason for s in result.skipped}
    assert reasons == {"big.py": "too_large", "blob.py": "binary"}
    assert result.unsupported_count == 1  # notes.md


def test_symlinks_are_skipped_and_loops_safe(tmp_path: Path) -> None:
    _write(tmp_path, "real.py", "x=1")
    os.symlink(tmp_path / "real.py", tmp_path / "link.py")
    os.symlink(tmp_path, tmp_path / "loop")
    repo = Repo(tmp_path)
    assert repo.paths == ["real.py"]
    result = repo.load()
    assert [(s.file, s.reason) for s in result.skipped] == [("link.py", "symlink")]


def test_repo_view_helpers(tmp_path: Path) -> None:
    _write(tmp_path, "supabase/config.toml", "a=1")
    _write(tmp_path, "supabase/migrations/1.sql", "select 1;")
    _write(tmp_path, "supabase/migrations/2.sql", "select 2;")
    repo = Repo(tmp_path)
    assert repo.exists("supabase/config.toml")
    assert not repo.exists("nope")
    assert repo.glob("supabase/migrations/*.sql") == [
        "supabase/migrations/1.sql",
        "supabase/migrations/2.sql",
    ]
    assert repo.glob("**/*.toml") == ["supabase/config.toml"]
    assert repo.read_text("supabase/config.toml") == "a=1"
