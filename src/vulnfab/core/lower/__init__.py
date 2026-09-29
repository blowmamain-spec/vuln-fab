"""Front-ends that lower parsed files into TIR."""

from __future__ import annotations

from vulnfab.core.models import ParsedFile
from vulnfab.core.tir import ModuleIR


def lower_file(pf: ParsedFile) -> ModuleIR:
    """Lower a parsed file (Python, JS/TS/TSX, PHP) into TIR."""
    root = pf.tree.root_node
    if pf.language == "python":
        from vulnfab.core.lower.python import PythonLowerer

        return PythonLowerer(pf.path, pf.source, root).lower()
    if pf.language in ("javascript", "typescript", "tsx"):
        from vulnfab.core.lower.javascript import JavaScriptLowerer

        lowerer = JavaScriptLowerer(pf.path, pf.source, root)
        module = lowerer.lower()
        module.language = pf.language
        return module
    if pf.language == "php":
        from vulnfab.core.lower.php import PhpLowerer

        return PhpLowerer(pf.path, pf.source, root).lower()
    raise ValueError(f"no TIR front-end for language {pf.language!r}")
