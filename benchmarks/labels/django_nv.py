"""Ground truth for django.nV built from the authors' own ``# A<n>:`` markers and tutorials.

    python benchmarks/labels/django_nv.py            # writes benchmarks/truth/django-nv.json

Every label states where it comes from: ``official`` (a marker in the repository or its bundled
tutorial) or ``reviewer`` (found by reading the code; not an author label).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "benchmarks" / "targets" / "django-nv"
APP = TARGET / "taskManager"
items: list[dict[str, object]] = []


def add(kind: str, file: str, start: int, end: int, cls: str, cwe: str, tier: str | None, note: str,
        scope: bool = True) -> None:  # fmt: skip
    items.append({"id": "", "kind": kind, "file": f"taskManager/{file}", "line_start": start,
                  "line_end": end, "class": cls, "cwe": [cwe], "tier": tier, "in_scope": scope,
                  "note": note})  # fmt: skip


def function_span(lines: list[str], marker_line: int) -> tuple[int, int, int]:
    """(def line, first body line, last line) of the function that follows a marker comment."""
    i = marker_line  # 1-based marker line; scan from the next line
    while not lines[i].lstrip().startswith("def "):
        i += 1
    start = i + 1
    indent = len(lines[i]) - len(lines[i].lstrip())
    j = i + 1
    while j < len(lines) and (
        not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent
    ):
        j += 1
    return start, start + 1, j


views = (APP / "views.py").read_text().split("\n")
for n, text in enumerate(views, start=1):
    m = re.match(r"\s*# A(\d+):", text)
    if not m:
        continue
    code = int(m.group(1))
    if code in (4, 8):
        start, _, end = function_span(views, n)
        span = views[start - 1 : end]
        if code == 4:
            gets = [start + k for k, line in enumerate(span) if ".objects.get(pk=" in line]
            if gets:
                add("vulnerable", "views.py", min(gets), max(gets), "idor", "CWE-639", "B",
                    "official: marker '# A4: IDOR' above the view")  # fmt: skip
        else:
            add("vulnerable", "views.py", start, start, "csrf-exempt", "CWE-352", "A",
                "official: marker '# A8: CSRF' (@csrf_exempt view)")  # fmt: skip
    elif code == 10:
        start, _, end = function_span(views, n)
        for k in range(start, end + 1):
            if "return redirect(" in views[k - 1] and "request.GET" in views[k - 1]:
                add("vulnerable", "views.py", k, k, "redirect", "CWE-601", "A",
                    "official: marker '# A10: Open Redirect' + tutorial")  # fmt: skip

# the remaining author markers use a slightly different comment shape
for k, text in enumerate(views, start=1):
    if re.match(r"\s*#\s*A1 - Injection \(SQLi\)", text):
        for j in range(k, min(k + 6, len(views))):
            if "curs.execute(" in views[j]:
                add("vulnerable", "views.py", j + 1, j + 4, "sqli", "CWE-89", "A",
                    "official: marker '#A1 - Injection (SQLi)' (%-formatted SQL)")  # fmt: skip
                break
    if re.match(r"@csrf_exempt", text) and "forgot_password" in views[k]:
        add("vulnerable", "views.py", k + 1, k + 1, "csrf-exempt", "CWE-352", "A",
            "reviewer: same @csrf_exempt pattern as the marked views")  # fmt: skip

misc = (APP / "misc.py").read_text().split("\n")
for n, text in enumerate(misc, start=1):
    if "A1: Injection (shell)" in text:
        for k in range(n, min(n + 8, len(misc))):
            if "os.system(" in misc[k]:
                add("vulnerable", "misc.py", k + 1, k + 1, "cmd-injection", "CWE-78", "A",
                    "official: marker '# A1: Injection (shell)'")  # fmt: skip
                break

settings = (APP / "settings.py").read_text().split("\n")


def line_of(pattern: str) -> int:
    return next(i for i, t in enumerate(settings, start=1) if re.match(pattern, t))


add("vulnerable", "settings.py", line_of(r"DEBUG\s*="), line_of(r"DEBUG\s*="), "debug-true", "CWE-489", "A",
    "official: marker '# A5: Security Misconfiguration'")  # fmt: skip
add("vulnerable", "settings.py", line_of(r"PASSWORD_HASHERS"), line_of(r"PASSWORD_HASHERS"), "password-hasher",
    "CWE-916", "A", "official: marker '# A6: Sensitive Data Exposure' (MD5)")  # fmt: skip
add("vulnerable", "settings.py", line_of(r"SESSION_SERIALIZER"), line_of(r"SESSION_SERIALIZER"), "pickle-session",
    "CWE-502", "A", "official: marker '# A2' + tutorial (PickleSerializer)")  # fmt: skip
add("vulnerable", "settings.py", line_of(r"SESSION_COOKIE_HTTPONLY"), line_of(r"SESSION_COOKIE_HTTPONLY"),
    "cookie-httponly", "CWE-1004", "A", "official: marker '# A2' block")  # fmt: skip
add("vulnerable", "settings.py", line_of(r"SECRET_KEY"), line_of(r"SECRET_KEY"), "secret-key", "CWE-798", "A",
    "reviewer: SECRET_KEY literal (the tutorial says a leaked key enables pickle RCE)")  # fmt: skip

forms = (APP / "forms.py").read_text().split("\n")
for n, text in enumerate(forms, start=1):
    if "# A2: Broken Authentication" in text:
        for k in range(n, min(n + 25, len(forms))):
            if re.match(r"\s*exclude\s*=", forms[k]):
                add("vulnerable", "forms.py", k + 1, k + 1, "modelform-all", "CWE-915", "A",
                    "official: marker '# A2' + tutorial (blacklist `exclude` lets is_superuser through)")  # fmt: skip
                break

templates = APP / "templates" / "taskManager"
for rel, official in (
    ("base_backend.html", True), ("tutorials/base.html", True), ("task_details.html", False),
    ("search.html", False), ("settings.html", False),
):  # fmt: skip
    for n, text in enumerate((templates / rel).read_text().split("\n"), start=1):
        if "|safe" in text:
            add("vulnerable", f"templates/taskManager/{rel}", n, n, "template-safe", "CWE-79", "A",
                "official tutorial (XSS: username|safe)" if official else "reviewer: same |safe pattern")  # fmt: skip

for n, item in enumerate(items, start=1):
    item["id"] = f"T{n:03d}"
out = ROOT / "benchmarks" / "truth" / "django-nv.json"
out.write_text(json.dumps({"target": "django-nv", "revision": "see benchmarks/targets.lock",
                           "exclude": ["taskManager/migrations/**", "taskManager/static/**", "taskManager/tests.py"],
                           "items": items}, indent=2, ensure_ascii=False) + "\n")  # fmt: skip
print(f"wrote {out} ({len(items)} items)")
