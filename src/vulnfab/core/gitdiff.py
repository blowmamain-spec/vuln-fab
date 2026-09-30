"""Changed files relative to a git ref, and the files that depend on them (WP-10.3)."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from vulnfab.core.modindex import ModuleIndex

# Changing one of these can alter findings anywhere (schema, routing, settings, dependencies).
GLOBAL_FILE = re.compile(
    r"(?:^|/)(?:settings[\w.-]*\.py|urls\.py|models(?:/[^/]+)?\.py|routes/[^/]+\.php|"
    r"config/[^/]+\.php|database/migrations/[^/]+|supabase/(?:config\.toml|migrations/[^/]+|seed[^/]*)|"
    r"\.env[\w.]*|composer\.json|package\.json|\.vulnfab\.ya?ml|\.vulnfabignore)$"
)
_JS_IMPORT = re.compile(
    r"""(?:import\s+(?:[^'"]*?\s+from\s+)?|export\s+[^'"]*?\s+from\s+|require\(\s*|import\(\s*)['"]([^'"]+)['"]"""
)
_PHP_USE = re.compile(r"^\s*use\s+([\w\\]+)", re.MULTILINE)


class GitError(Exception):
    pass


def _git(root: Path, *args: str) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"cannot run git: {exc}") from exc
    if done.returncode != 0:
        raise GitError(done.stderr.strip() or f"git {' '.join(args)} failed")
    return done.stdout


def changed_files(root: Path, ref: str) -> set[str]:
    """Paths (relative to ``root``) that differ from ``ref`` in the working tree, plus new files."""
    _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    tracked = _git(root, "diff", "--name-only", "--relative", "--diff-filter=d", ref, "--", ".")
    untracked = _git(root, "ls-files", "--others", "--exclude-standard")
    return {line.strip() for line in (tracked + "\n" + untracked).splitlines() if line.strip()}


def import_graph(files: dict[str, tuple[str, str]]) -> dict[str, set[str]]:
    """file -> files it imports (Python, JS/TS resolved; PHP by class-name reference)."""
    index = ModuleIndex({path: lang for path, (lang, _) in files.items()})
    graph: dict[str, set[str]] = {path: set() for path in files}
    php_classes: dict[str, str] = {
        Path(p).stem: p for p, (lang, _) in files.items() if lang == "php" and p.endswith(".php")
    }
    for path, (lang, text) in files.items():
        targets: set[str] = set()
        if lang == "python":
            targets |= _python_imports(index, path, text)
        elif lang in ("javascript", "typescript", "tsx"):
            for module in _JS_IMPORT.findall(text):
                hit = index.resolve(path, module)
                if hit:
                    targets.add(hit)
        elif lang == "php":
            for name, owner in php_classes.items():
                if owner != path and re.search(rf"\b{re.escape(name)}\b", text):
                    targets.add(owner)
        targets.discard(path)
        graph[path] = targets
    return graph


def _python_imports(index: ModuleIndex, path: str, text: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                hit = index.resolve(path, alias.name)
                if hit:
                    out.add(hit)
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            hit = index.resolve(path, base) if base.strip(".") or node.level else None
            if hit:
                out.add(hit)
            for alias in node.names:  # `from pkg import module`
                sub = index.resolve(
                    path, f"{base}.{alias.name}" if base.strip(".") else f"{base}{alias.name}"
                )
                if sub:
                    out.add(sub)
    return out


def affected_files(changed: set[str], files: dict[str, tuple[str, str]]) -> tuple[set[str], bool]:
    """(files whose findings may change, everything-is-affected flag)."""
    if any(GLOBAL_FILE.search(c) for c in changed):
        return set(files), True
    graph = import_graph(files)
    reverse: dict[str, set[str]] = {}
    for src, targets in graph.items():
        for target in targets:
            reverse.setdefault(target, set()).add(src)
    affected = {c for c in changed if c in files}
    frontier = list(affected)
    while frontier:
        current = frontier.pop()
        for dependent in reverse.get(current, ()):
            if dependent not in affected:
                affected.add(dependent)
                frontier.append(dependent)
    return affected, False


def local_only_files(root: Path) -> set[str]:
    """Untracked files ignored by git (never committed). Empty outside a git work tree."""
    try:
        out = _git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
    except GitError:
        return set()
    return {p for p in out.split("\0") if p}
