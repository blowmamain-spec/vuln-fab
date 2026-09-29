"""Resolve import strings to files of the scanned project (Python and JS/TS)."""

from __future__ import annotations

import posixpath

JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
JS_LANGS = ("javascript", "typescript", "tsx")


class ModuleIndex:
    def __init__(self, files: dict[str, str]) -> None:
        """``files`` maps path -> language."""
        self.files = files
        self._stems: dict[str, list[str]] = {}
        for path in files:
            stem = path.rsplit(".", 1)[0]
            self._stems.setdefault(stem, []).append(path)
            if posixpath.basename(stem) in ("index", "__init__"):
                self._stems.setdefault(posixpath.dirname(stem), []).append(path)
        self._cache: dict[tuple[str, str], str | None] = {}

    def resolve(self, from_file: str, module: str) -> str | None:
        key = (from_file, module)
        if key not in self._cache:
            language = self.files.get(from_file, "")
            if language == "python":
                found = self._python(from_file, module)
            elif language in JS_LANGS:
                found = self._js(from_file, module)
            else:
                found = None
            self._cache[key] = found
        return self._cache[key]

    def _pick(self, stem: str, from_file: str, *, suffix: bool) -> str | None:
        stem = stem.strip("/")
        if stem in self._stems:
            options = self._stems[stem]
        elif suffix:
            options = [p for s, ps in self._stems.items() if s.endswith("/" + stem) for p in ps]
        else:
            return None
        lang_ok = [
            p
            for p in options
            if (self.files[p] == "python") == (self.files.get(from_file) == "python")
        ]
        unique = sorted(set(lang_ok))
        exact = [p for p in unique if not posixpath.basename(p).startswith(("index.", "__init__."))]
        pool = exact or unique
        return pool[0] if len(pool) == 1 else None

    def _js(self, from_file: str, module: str) -> str | None:
        if module.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(from_file), module))
            return self._pick(
                base.rsplit(".", 1)[0] if base.endswith(JS_EXTS) else base, from_file, suffix=False
            )
        aliased = module.startswith(("@/", "~/"))
        if module.startswith("@") and not aliased:
            return None  # scoped npm package
        stripped = module[2:] if aliased else module
        if not aliased and "/" not in stripped:
            return None  # bare package name
        return self._pick(stripped, from_file, suffix=True)

    def _python(self, from_file: str, module: str) -> str | None:
        dots = len(module) - len(module.lstrip("."))
        rest = module.lstrip(".").replace(".", "/")
        if dots:
            base = posixpath.dirname(from_file)
            for _ in range(dots - 1):
                base = posixpath.dirname(base)
            return self._pick(posixpath.join(base, rest) if rest else base, from_file, suffix=False)
        return self._pick(rest, from_file, suffix=True) if rest else None
