"""Guard against py-tree-sitter 0.26.0's Point refcount bug (use-after-free, found via valgrind).

Never read ``Node.start_point`` / ``end_point``; use ``vulnfab.core.parsing.node_lines``.
"""

from pathlib import Path

from vulnfab.core.models import SourceFile
from vulnfab.core.parsing import line_of, node_lines, parse_file, walk

SRC = Path(__file__).resolve().parents[2] / "src" / "vulnfab"


def test_source_does_not_use_point_api() -> None:
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if p.name != "parsing.py"
        and ("start_point" in p.read_text() or "end_point" in p.read_text())
    ]
    assert offenders == []


def test_line_helpers() -> None:
    src = b"a\nb\nc\n"
    assert [line_of(src, i) for i in range(len(src))] == [1, 1, 2, 2, 3, 3]
    pf = parse_file(SourceFile("t.py", "python", "x = 1\nf(\n  a,\n  b)\n", "0" * 64))
    call = next(n for n in walk(pf.tree.root_node) if n.type == "call")
    assert node_lines(call, pf.source) == (2, 4)
