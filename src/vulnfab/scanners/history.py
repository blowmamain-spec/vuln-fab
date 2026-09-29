"""Opt-in scan of git history for secrets that were committed once (WP-8.3).

Only lines *added* by a commit are examined. A secret that is still present in the working tree
is left to the normal scan (``sec-secret-hardcoded``); this reports the ones that were removed
from the tree but remain recoverable from history and must therefore be rotated.
"""

from __future__ import annotations

import re
from pathlib import Path

from vulnfab.core.gitdiff import GitError, _git
from vulnfab.core.models import Confidence, Finding, Severity, SourceFile
from vulnfab.scanners.secrets import _redact, scan_file

RULE_ID = "sec-secret-history"
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")
DEFAULT_LIMIT = 200


def _language(path: str) -> str:
    from vulnfab.core.loader import detect_language

    return detect_language(path.rsplit("/", 1)[-1]) or "text"


def history_findings(
    root: Path, current: dict[str, str], limit: int = DEFAULT_LIMIT
) -> tuple[list[Finding], list[str]]:
    """Return ``(findings, notes)``. ``current`` maps path -> text of files in the working tree."""
    notes: list[str] = []
    try:
        shas = _git(root, "rev-list", f"--max-count={limit}", "HEAD").split()
        total = int(_git(root, "rev-list", "--count", "HEAD").strip() or 0)
    except GitError as exc:
        return [], [f"git history was NOT scanned: {exc}"]
    if total > len(shas):
        notes.append(
            f"git history: only the newest {len(shas)} of {total} commits were scanned "
            "(raise --history-limit)."
        )
    tree_text = "\n".join(current.values())
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for sha in shas:
        try:
            diff = _git(root, "show", "--format=", "--unified=0", "--no-color", sha)
        except GitError:
            continue
        path = ""
        lines: dict[int, str] = {}
        chunks: list[tuple[str, dict[int, str]]] = []
        number = 0
        for raw in diff.split("\n"):
            if raw.startswith("+++ "):
                if path and lines:
                    chunks.append((path, lines))
                path, lines = (raw[6:] if raw.startswith("+++ b/") else ""), {}
            elif (m := _HUNK.match(raw)) is not None:
                number = int(m.group(1))
            elif raw.startswith("+") and not raw.startswith("+++"):
                lines[number] = raw[1:]
                number += 1
        if path and lines:
            chunks.append((path, lines))
        for file, added in chunks:
            top = max(added)
            text = "\n".join(added.get(i, "") for i in range(1, top + 1))
            sf = SourceFile(file, _language(file), text, "0" * 64)
            for line, what, snippet, confidence in scan_file(sf):
                if snippet in tree_text or (file, what) in seen:
                    continue  # still in the tree: the normal scan reports it
                seen.add((file, what))
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        title="Secret present in git history",
                        cwe=("CWE-798",),
                        owasp="A07:2021",
                        severity=Severity.HIGH,
                        confidence=confidence or Confidence.MEDIUM,
                        tier="A",
                        file=file,
                        line=line,
                        end_line=line,
                        snippet=_redact(snippet),
                        fix="Rotate the credential; deleting it from the tree does not remove it "
                        "from history.",
                        message=f"{what} was committed in {sha[:10]} and is still recoverable "
                        "from git history.",
                    )
                )
    return findings, notes
