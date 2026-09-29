"""Repository loader: walk, ignore, hash, classify (WP-1.1)."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from vulnfab.core.models import SourceFile

DEFAULT_MAX_FILE_BYTES = 1024 * 1024
IGNORE_FILE = ".vulnfabignore"

DEFAULT_IGNORE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".venv", "venv", ".tox",
        ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build", ".next", ".nuxt",
        ".vulnfab-cache",
    }
)  # fmt: skip

_EXTENSION_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".php": "php",
    ".sql": "sql",
    ".toml": "toml",
    ".html": "html", ".htm": "html",
    ".json": "json",
    ".yml": "yaml", ".yaml": "yaml",
}  # fmt: skip

_NAME_LANGUAGE = {
    "dockerfile": "dockerfile",
    "nginx.conf": "nginx",
    "composer.json": "json",
}


def detect_language(rel_path: str) -> str | None:
    """Map a relative path to a language id, or ``None`` if the file is not of interest."""
    name = rel_path.rsplit("/", 1)[-1]
    lower = name.lower()
    if lower.endswith(".blade.php"):
        return "blade"
    if lower == ".env" or lower.startswith(".env."):
        return "env"
    if lower in _NAME_LANGUAGE:
        return _NAME_LANGUAGE[lower]
    if lower.startswith("dockerfile."):
        return "dockerfile"
    dot = lower.rfind(".")
    return _EXTENSION_LANGUAGE.get(lower[dot:]) if dot >= 0 else None


# --- ignore patterns (gitignore-like) -------------------------------------------------------


def _glob_to_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == n:
            out.append("/.*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            j = pattern.find("]", i + 1)
            if j < 0:
                out.append(re.escape(ch))
                i += 1
            else:
                body = pattern[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class _IgnoreRule:
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


class IgnoreMatcher:
    """Minimal gitignore semantics: comments, negation, anchoring, dir-only, ``**``."""

    def __init__(self, patterns: list[str] | None = None) -> None:
        self._rules: list[_IgnoreRule] = []
        for line in patterns or []:
            self.add(line)

    @classmethod
    def from_file(cls, path: Path) -> IgnoreMatcher:
        if not path.is_file():
            return cls()
        return cls(path.read_text(encoding="utf-8", errors="replace").splitlines())

    def add(self, line: str) -> None:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            return
        negate = pattern.startswith("!")
        if negate:
            pattern = pattern[1:]
        dir_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        if not pattern:
            return
        anchored = pattern.startswith("/") or "/" in pattern
        pattern = pattern.lstrip("/")
        body = _glob_to_regex(pattern)
        prefix = "" if anchored else "(?:.*/)?"
        self._rules.append(_IgnoreRule(re.compile(f"^{prefix}{body}$"), negate, dir_only))

    def is_ignored(self, rel_path: str, is_dir: bool) -> bool:
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(rel_path):
                ignored = not rule.negate
        return ignored


# --- repository view ------------------------------------------------------------------------


@dataclass(frozen=True)
class SkippedFile:
    file: str
    reason: str  # too_large | binary | unreadable | symlink | parse_error | timeout
    detail: str = ""


@dataclass
class LoadResult:
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    ignored_count: int = 0
    unsupported_count: int = 0


class Repo:
    """Concrete :class:`vulnfab.plugins.base.RepoView` backed by the filesystem."""

    def __init__(
        self,
        root: Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        extra_ignore: list[str] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.max_file_bytes = max_file_bytes
        self._ignore = IgnoreMatcher.from_file(self.root / IGNORE_FILE)
        for line in extra_ignore or []:
            self._ignore.add(line)
        self.ignored_count = 0
        self._symlinks: list[str] = []
        self.paths: list[str] = self._walk()
        self._pathset = frozenset(self.paths)

    def _walk(self) -> list[str]:
        found: list[str] = []
        stack = [""]
        while stack:
            rel_dir = stack.pop()
            try:
                entries = sorted(os.scandir(self.root / rel_dir if rel_dir else self.root),
                                 key=lambda e: e.name)  # fmt: skip
            except OSError:
                continue
            subdirs: list[str] = []
            for entry in entries:
                rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                if entry.is_symlink():
                    if entry.is_file(follow_symlinks=True):
                        self._symlinks.append(rel)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in DEFAULT_IGNORE_DIRS or self._ignore.is_ignored(rel, True):
                        self.ignored_count += 1
                        continue
                    subdirs.append(rel)
                elif entry.is_file(follow_symlinks=False):
                    if self._ignore.is_ignored(rel, False):
                        self.ignored_count += 1
                        continue
                    found.append(rel)
            stack.extend(reversed(subdirs))
        found.sort()
        return found

    # RepoView protocol
    def exists(self, rel_path: str) -> bool:
        return rel_path in self._pathset

    def read_text(self, rel_path: str) -> str:
        return (self.root / rel_path).read_text(encoding="utf-8-sig", errors="replace")

    def glob(self, pattern: str) -> list[str]:
        regex = re.compile("^" + _glob_to_regex(pattern.lstrip("/")) + "$")
        return [p for p in self.paths if regex.match(p)]

    def load(self, only_languages: set[str] | None = None) -> LoadResult:
        result = LoadResult(ignored_count=self.ignored_count)
        for rel in self._symlinks:
            result.skipped.append(SkippedFile(rel, "symlink"))
        for rel in self.paths:
            language = detect_language(rel)
            if language is None or (only_languages is not None and language not in only_languages):
                result.unsupported_count += 1
                continue
            path = self.root / rel
            try:
                size = path.stat().st_size
                if size > self.max_file_bytes:
                    result.skipped.append(SkippedFile(rel, "too_large", f"{size} bytes"))
                    continue
                data = path.read_bytes()
            except OSError as exc:
                result.skipped.append(SkippedFile(rel, "unreadable", str(exc)))
                continue
            if b"\x00" in data[:8192]:
                result.skipped.append(SkippedFile(rel, "binary"))
                continue
            text = data.decode("utf-8-sig", errors="replace")
            result.files.append(
                SourceFile(
                    path=rel,
                    language=language,
                    text=text,
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            )
        return result
