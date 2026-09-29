"""Verdict store shared by ``vulnfab triage`` and the benchmark evaluator (WP-9.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VALID = ("tp", "fp", "dup")


class TriageError(Exception):
    pass


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"verdicts": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise TriageError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("verdicts", {}), dict):
        raise TriageError(f"{path} does not look like a verdict file")
    data.setdefault("verdicts", {})
    return data


def save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = dict(sorted(data["verdicts"].items()))
    path.write_text(
        json.dumps({**data, "verdicts": ordered}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def set_verdicts(
    path: Path, fingerprints: list[str], verdict: str, note: str = "", reviewer: str = ""
) -> int:
    if verdict not in VALID:
        raise TriageError(f"verdict must be one of {', '.join(VALID)}")
    data = load(path)
    for fingerprint in fingerprints:
        entry: dict[str, str] = {"verdict": verdict}
        if note:
            entry["note"] = note
        data["verdicts"][fingerprint] = entry
    if reviewer:
        data["reviewer"] = reviewer
    save(path, data)
    return len(fingerprints)


def clear(path: Path, fingerprints: list[str]) -> int:
    data = load(path)
    removed = sum(1 for fp in fingerprints if data["verdicts"].pop(fp, None) is not None)
    save(path, data)
    return removed


def unreviewed(findings_json: Path, verdict_file: Path) -> list[dict[str, Any]]:
    document = json.loads(findings_json.read_text(encoding="utf-8"))
    findings = document["findings"] if isinstance(document, dict) else document
    known = load(verdict_file)["verdicts"]
    return [f for f in findings if f.get("fingerprint") not in known]
