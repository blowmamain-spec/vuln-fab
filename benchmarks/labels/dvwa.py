"""Ground truth for DVWA from its own difficulty levels.

    python benchmarks/labels/dvwa.py     # writes benchmarks/truth/dvwa.json

DVWA ships every vulnerability at four levels. ``low`` (and, where verified by reading, ``medium``
and ``high``) are vulnerable by design; ``impossible`` is the maintainers' reference fix, so it is
a decoy. Lines were read by hand; the ``note`` says whether the label follows DVWA's design
(``official``) or my own reading (``reviewer``).
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V = "vulnerabilities"
items: list[dict[str, object]] = []


def add(
    kind: str,
    file: str,
    lines: tuple[int, int] | int,
    cls: str,
    cwe: str,
    note: str,
    tier: str = "A",
) -> None:
    start, end = (lines, lines) if isinstance(lines, int) else lines
    items.append({"id": "", "kind": kind, "file": file, "line_start": start, "line_end": end, "class": cls,
                  "cwe": [cwe], "tier": tier if kind == "vulnerable" else None, "in_scope": True, "note": note})  # fmt: skip


def vuln(file: str, lines: int | tuple[int, int], cls: str, cwe: str, note: str) -> None:
    add("vulnerable", file, lines, cls, cwe, note)


def decoy(file: str, lines: int | tuple[int, int], cls: str, cwe: str, note: str) -> None:
    add("decoy", file, lines, cls, cwe, note)


# --- SQL injection -----------------------------------------------------------------------------
for level, mysql, sqlite in (("low", 11, 34), ("medium", 12, 30), ("high", 11, 31)):
    why = {"low": "official: level low", "medium": "official: escape_string in a numeric context does not help",
           "high": "official: value comes from a session id the user sets; LIMIT 1 is bypassed by a comment"}[level]  # fmt: skip
    vuln(f"{V}/sqli/source/{level}.php", mysql, "sqli", "CWE-89", why)
    vuln(f"{V}/sqli/source/{level}.php", sqlite, "sqli", "CWE-89", why)
for level, mysql, sqlite in (("low", 13, 34), ("medium", 15, 36), ("high", 13, 35)):
    vuln(
        f"{V}/sqli_blind/source/{level}.php",
        mysql,
        "sqli",
        "CWE-89",
        f"official: blind SQLi, level {level}",
    )
    vuln(
        f"{V}/sqli_blind/source/{level}.php",
        sqlite,
        "sqli",
        "CWE-89",
        f"official: blind SQLi, level {level}",
    )
vuln(
    f"{V}/brute/source/low.php",
    13,
    "sqli",
    "CWE-89",
    "reviewer: username concatenated into the login query",
)
decoy(f"{V}/sqli/source/impossible.php", 16, "sqli", "CWE-89", "official: PDO prepared statement")
decoy(
    f"{V}/sqli/source/impossible.php", 34, "sqli", "CWE-89", "official: SQLite3 prepared statement"
)
decoy(
    f"{V}/sqli_blind/source/impossible.php",
    17,
    "sqli",
    "CWE-89",
    "official: PDO prepared statement",
)
decoy(
    f"{V}/sqli_blind/source/impossible.php",
    26,
    "sqli",
    "CWE-89",
    "official: SQLite3 prepared statement",
)
decoy(f"{V}/brute/source/impossible.php", 24, "sqli", "CWE-89", "official: PDO prepared statement")
decoy(f"{V}/brute/source/impossible.php", 53, "sqli", "CWE-89", "official: PDO prepared statement")
decoy(
    f"{V}/csrf/source/low.php",
    17,
    "sqli",
    "CWE-89",
    "reviewer: value escaped and md5-hashed before the query",
)
decoy(
    f"{V}/captcha/source/low.php",
    61,
    "sqli",
    "CWE-89",
    "reviewer: value escaped and md5-hashed before the query",
)
decoy(
    f"{V}/xss_s/source/low.php",
    17,
    "sqli",
    "CWE-89",
    "reviewer: both values escaped before the INSERT",
)

# --- command injection -------------------------------------------------------------------------
for level, unix, windows in (("low", 14, 10), ("medium", 23, 19), ("high", 30, 26)):
    note = {"low": "official: level low", "medium": "official: blacklist of && and ; is bypassed with | or &",
            "high": "official: blacklist has '| ' with a space; '|' alone still works"}[level]  # fmt: skip
    vuln(f"{V}/exec/source/{level}.php", windows, "cmd-injection", "CWE-78", note)
    vuln(f"{V}/exec/source/{level}.php", unix, "cmd-injection", "CWE-78", note)
decoy(
    f"{V}/exec/source/impossible.php",
    22,
    "cmd-injection",
    "CWE-78",
    "official: input must be four numeric octets",
)
decoy(
    f"{V}/exec/source/impossible.php",
    26,
    "cmd-injection",
    "CWE-78",
    "official: input must be four numeric octets",
)

# --- open redirect, XSS, file access -------------------------------------------------------------
vuln(f"{V}/open_redirect/source/low.php", 4, "redirect", "CWE-601", "official: level low")
decoy(
    f"{V}/open_redirect/source/impossible.php",
    18,
    "redirect",
    "CWE-601",
    "official: target chosen from constants",
)
vuln(
    f"{V}/xss_r/source/low.php",
    8,
    "xss",
    "CWE-79",
    "official: reflected XSS, level low (output happens via $html elsewhere)",
)
decoy(f"{V}/xss_r/source/impossible.php", 12, "xss", "CWE-79", "official: htmlspecialchars")
vuln(
    f"{V}/fi/index.php",
    36,
    "path-traversal",
    "CWE-98",
    "official: file inclusion (the path is set in source/<level>.php)",
)
for line in (14, 18, 22, 26):
    vuln(
        f"{V}/view_source_all.php",
        line,
        "path-traversal",
        "CWE-22",
        "reviewer: ?id= is concatenated into a file path",
    )
for line in (63, 68):
    vuln(
        f"{V}/view_source.php",
        line,
        "path-traversal",
        "CWE-22",
        "reviewer: ?id= is concatenated into a file path",
    )

for n, item in enumerate(items, start=1):
    item["id"] = f"{'T' if item['kind'] == 'vulnerable' else 'D'}{n:03d}"
out = ROOT / "benchmarks" / "truth" / "dvwa.json"
out.write_text(json.dumps({"target": "dvwa", "revision": "see benchmarks/targets.lock",
                           "exclude": ["tests/**", "external/**", "vulnerabilities/*/test_*/**"], "items": items},
                          indent=2, ensure_ascii=False) + "\n")  # fmt: skip
print(f"wrote {out} ({len(items)} items)")
