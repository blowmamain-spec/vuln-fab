"""Module specifier resolution for TypeScript/JavaScript projects (relative + common aliases)."""

from __future__ import annotations

import posixpath

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
INDEX_FILES = tuple(f"index{ext}" for ext in EXTENSIONS)
# Frequent tsconfig "paths" aliases; tried against every project root that has such a directory.
ALIAS_PREFIXES = ("@/", "~/", "#/")


def _candidates(base: str) -> list[str]:
    out = [base]
    stem, ext = posixpath.splitext(base)
    if ext in (".js", ".jsx", ".mjs", ".cjs"):  # TS projects import "./x.js" for "./x.ts"
        out.extend(stem + e for e in EXTENSIONS)
    out.extend(base + e for e in EXTENSIONS)
    out.extend(posixpath.join(base, name) for name in INDEX_FILES)
    return out


def resolve_module(from_path: str, spec: str, known: set[str]) -> str | None:
    """Return the repo-relative path a specifier points to, or ``None`` (packages, unknown)."""
    if spec.startswith("."):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
        return next((c for c in _candidates(base) if c in known), None)
    for prefix in ALIAS_PREFIXES:
        if spec.startswith(prefix):
            rest = spec[len(prefix) :]
            roots = _alias_roots(from_path)
            for root in roots:
                for candidate in _candidates(posixpath.normpath(posixpath.join(root, rest))):
                    if candidate in known:
                        return candidate
    return None


def _alias_roots(from_path: str) -> list[str]:
    """Ancestor directories, each also tried with a ``src`` child (``@/*`` -> ``src/*``)."""
    parts = from_path.split("/")[:-1]
    roots: list[str] = []
    for i in range(len(parts), -1, -1):
        base = "/".join(parts[:i])
        roots.append(posixpath.join(base, "src") if base else "src")
        roots.append(base)
    return roots
