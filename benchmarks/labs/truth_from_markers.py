"""Generate ground truth JSON from ``@lab`` markers in a lab directory.

Usage:
    python benchmarks/labs/truth_from_markers.py supabase-vuln            # write truth file
    python benchmarks/labs/truth_from_markers.py supabase-vuln --check    # fail if out of date
    python benchmarks/labs/truth_from_markers.py supabase-vuln --show     # print labelled ranges
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRUTH_DIR = HERE.parent / "truth"
MARKER_RE = re.compile(
    r"^\s*(?:--|//|#|\{#|\{\{--|<!--)\s*@lab\s+(?P<kind>vuln|decoy)\s+(?P<cls>[a-z0-9-]+)(?P<rest>.*?)"
    r"(?:\s*(?:#\}|--\}\}|-->))?\s*$"
)
TEXT_SUFFIXES = {".sql", ".ts", ".tsx", ".js", ".toml", ".local", ".env", ".py", ".php", ".html", ".example"}
SKIP_DIRS = {"node_modules", ".git"}


class MarkerError(Exception):
    pass


def _parse_rest(rest: str) -> tuple[dict[str, str], str]:
    head, _, note = rest.partition("::")
    options: dict[str, str] = {}
    for token in head.split():
        key, sep, value = token.partition("=")
        if not sep:
            raise MarkerError(f"bad option {token!r}")
        options[key] = value
    return options, note.strip()


def collect(lab: Path) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for path in sorted(p for p in lab.rglob("*") if p.is_file()):
        if SKIP_DIRS & set(path.relative_to(lab).parts):
            continue
        if path.suffix not in TEXT_SUFFIXES and path.name not in {".env.local"}:
            continue
        rel = path.relative_to(lab).as_posix()
        lines = path.read_text().split("\n")
        pending: list[tuple[re.Match[str], int]] = []
        for number, line in enumerate(lines, start=1):
            m = MARKER_RE.match(line)
            if m:
                pending.append((m, number))
                continue
            if pending:
                for marker, marker_line in pending:
                    options, note = _parse_rest(marker.group("rest"))
                    count = int(options.pop("lines", "1"))
                    cwe = [c for c in options.pop("cwe", "").split(",") if c]
                    tier = options.pop("tier", None)
                    in_scope = options.pop("in_scope", "true") != "false"
                    if options:
                        raise MarkerError(f"{rel}:{marker_line}: unknown options {sorted(options)}")
                    item: dict[str, object] = {
                        "kind": "vulnerable" if marker.group("kind") == "vuln" else "decoy",
                        "file": rel,
                        "line_start": number,
                        "line_end": number + count - 1,
                        "class": marker.group("cls"),
                        "cwe": cwe,
                        "tier": tier,
                        "in_scope": in_scope,
                        "note": note,
                    }
                    if number + count - 1 > len(lines):
                        raise MarkerError(f"{rel}:{marker_line}: range beyond end of file")
                    items.append(item)
                pending = []
        if pending:
            raise MarkerError(f"{rel}:{pending[-1][1]}: marker without a following line")
    return items


def build(lab_name: str) -> dict[str, object]:
    items = collect(HERE / lab_name)
    counters = {"vulnerable": 0, "decoy": 0}
    for item in items:
        kind = str(item["kind"])
        counters[kind] += 1
        prefix = "T" if kind == "vulnerable" else "D"
        item["id"] = f"{prefix}{counters[kind]:03d}"
    ordered = [{"id": i.pop("id"), **i} for i in items]
    return {"target": lab_name, "revision": "lab-1", "items": ordered}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lab")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args()
    truth = build(args.lab)
    text = json.dumps(truth, indent=2, ensure_ascii=False) + "\n"
    out = TRUTH_DIR / f"{args.lab}.json"
    if args.show:
        lab = HERE / args.lab
        for item in truth["items"]:  # type: ignore[attr-defined]
            body = (lab / item["file"]).read_text().split("\n")
            print(f"{item['id']} {item['kind'][:4]} {item['class']} {item['file']}:{item['line_start']}-{item['line_end']}")
            for n in range(item["line_start"], item["line_end"] + 1):
                print(f"    {n:>3} | {body[n - 1]}")
        return 0
    if args.check:
        if not out.exists() or out.read_text() != text:
            print(f"{out} is out of date; regenerate it", file=sys.stderr)
            return 1
        return 0
    TRUTH_DIR.mkdir(exist_ok=True)
    out.write_text(text)
    print(f"wrote {out} ({len(truth['items'])} items)")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
