"""Download OSV advisories into a compact offline database (WP-8.2 follow-up).

``vulnfab osv update DIR`` fetches ``<base>/<ecosystem>/all.zip`` and stores one JSON-lines file
per ecosystem containing only the fields the scanner uses. Scanning itself stays offline.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
ECOSYSTEMS = ("npm", "PyPI", "Packagist")
KEEP = ("id", "aliases", "summary", "withdrawn", "affected", "database_specific")
MAX_ZIP_BYTES = 2_000_000_000


class OsvUpdateError(Exception):
    pass


def _download(url: str, timeout: float) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed https base
            data: bytes = resp.read(MAX_ZIP_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise OsvUpdateError(f"cannot download {url}: {exc}") from exc
    if len(data) > MAX_ZIP_BYTES:
        raise OsvUpdateError(f"{url}: archive larger than {MAX_ZIP_BYTES} bytes")
    return data


def _compact(record: dict[str, object]) -> dict[str, object]:
    out = {k: record[k] for k in KEEP if k in record}
    affected = []
    for entry in record.get("affected") or []:  # type: ignore[attr-defined]
        if isinstance(entry, dict):
            affected.append({k: entry[k] for k in ("package", "ranges", "versions") if k in entry})
    out["affected"] = affected
    return out


def convert_zip(data: bytes) -> tuple[list[str], int]:
    """Return JSON lines (one per advisory) and the number of skipped entries."""
    lines: list[str] = []
    skipped = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise OsvUpdateError(f"not a zip archive: {exc}") from exc
    for name in sorted(archive.namelist()):
        if not name.endswith(".json"):
            continue
        try:
            record = json.loads(archive.read(name))
        except ValueError:
            skipped += 1
            continue
        if isinstance(record, dict) and record.get("id"):
            lines.append(json.dumps(_compact(record), separators=(",", ":"), sort_keys=True))
        else:
            skipped += 1
    return lines, skipped


def update(
    dest: Path,
    ecosystems: tuple[str, ...] = ECOSYSTEMS,
    base_url: str = BASE_URL,
    timeout: float = 300.0,
) -> dict[str, int]:
    """Refresh ``dest``. Existing data for an ecosystem is replaced only after a full success."""
    dest.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for eco in ecosystems:
        lines, _ = convert_zip(_download(f"{base_url.rstrip('/')}/{eco}/all.zip", timeout))
        fd, tmp = tempfile.mkstemp(dir=dest, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        os.replace(tmp, dest / f"{eco}.jsonl")
        counts[eco] = len(lines)
    (dest / "osv-meta.json").write_text(
        json.dumps(
            {"updated": datetime.now(UTC).isoformat(timespec="seconds"), "advisories": counts},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return counts
