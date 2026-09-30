"""Software composition analysis without a network: lockfiles x a local OSV database (WP-8.2).

The OSV database is a directory of advisory files (``*.json`` / ``*.jsonl`` in the OSV schema) or a
single JSON file, given with ``--osv-db``. Nothing is downloaded. An optional adapter can run the
``osv-scanner`` binary instead (``--osv-scanner``).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from vulnfab.core.models import Confidence, Severity, SourceFile
from vulnfab.core.report import AdapterStatus
from vulnfab.core.scannerrules import ScannerContext, ScannerHit

SEVERITY_BY_LABEL = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
LOCKFILE_NAMES = ("package-lock.json", "composer.lock", "poetry.lock", "uv.lock", "pipfile.lock")


@dataclass(frozen=True)
class Package:
    ecosystem: str  # npm | Packagist | PyPI
    name: str
    version: str
    needle: str  # text used to find the package's line in the lockfile


def is_lockfile(sf: SourceFile) -> bool:
    name = sf.path.rsplit("/", 1)[-1].lower()
    return name in LOCKFILE_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


# --- lockfile parsers ---


def _normalise_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lockfile(sf: SourceFile) -> list[Package]:
    name = sf.path.rsplit("/", 1)[-1].lower()
    try:
        if name == "package-lock.json":
            return _package_lock(json.loads(sf.text))
        if name == "composer.lock":
            return _composer_lock(json.loads(sf.text))
        if name == "pipfile.lock":
            return _pipfile_lock(json.loads(sf.text))
        if name in ("poetry.lock", "uv.lock"):
            return _toml_lock(tomllib.loads(sf.text))
        if name.startswith("requirements"):
            return _requirements(sf.text)
    except (ValueError, tomllib.TOMLDecodeError, TypeError, AttributeError):
        return []
    return []


def _package_lock(data: dict[str, Any]) -> list[Package]:
    out: list[Package] = []
    for path, meta in (data.get("packages") or {}).items():  # lockfileVersion 2/3
        if not path or not isinstance(meta, dict) or "version" not in meta or meta.get("link"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        out.append(Package("npm", name, str(meta["version"]), f'"{path}"'))
    if not out:  # lockfileVersion 1

        def walk(deps: dict[str, Any]) -> None:
            for name, meta in deps.items():
                if isinstance(meta, dict) and "version" in meta:
                    out.append(Package("npm", name, str(meta["version"]), f'"{name}"'))
                    walk(meta.get("dependencies") or {})

        walk(data.get("dependencies") or {})
    return out


def _composer_lock(data: dict[str, Any]) -> list[Package]:
    out: list[Package] = []
    for group in ("packages", "packages-dev"):
        for meta in data.get(group) or []:
            if isinstance(meta, dict) and "name" in meta and "version" in meta:
                out.append(
                    Package(
                        "Packagist",
                        meta["name"],
                        str(meta["version"]).lstrip("v"),
                        f'"name": "{meta["name"]}"',
                    )
                )
    return out


def _pipfile_lock(data: dict[str, Any]) -> list[Package]:
    out: list[Package] = []
    for group in ("default", "develop"):
        for name, meta in (data.get(group) or {}).items():
            version = str((meta or {}).get("version", "")).lstrip("=")
            if version:
                out.append(Package("PyPI", _normalise_py(name), version, f'"{name}"'))
    return out


def _toml_lock(data: dict[str, Any]) -> list[Package]:
    out: list[Package] = []
    for meta in data.get("package") or []:
        if isinstance(meta, dict) and "name" in meta and "version" in meta:
            out.append(
                Package(
                    "PyPI",
                    _normalise_py(meta["name"]),
                    str(meta["version"]),
                    f'name = "{meta["name"]}"',
                )
            )
    return out


def _requirements(text: str) -> list[Package]:
    out: list[Package] = []
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip()
        m = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)", line
        )
        if m:
            out.append(Package("PyPI", _normalise_py(m.group(1)), m.group(2), line))
    return out


# --- versions ---

_PRE = re.compile(r"(?i)(a|alpha|b|beta|rc|c|pre|preview|dev)[.-]?\d*")


def version_key(version: str) -> tuple[Any, ...]:
    """Comparable key: numeric release parts, then 'final beats pre-release'. Approximates semver,
    PEP 440 and Composer ordering; build metadata is ignored."""
    v = version.strip().lstrip("vV").split("+", 1)[0]
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), 1, v)
    release = tuple(int(x) for x in m.group(1).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    tail = m.group(2).lstrip(".-_")
    pre = bool(tail) and bool(_PRE.match(tail)) and not re.match(r"(?i)^(post|p)\d*", tail)
    return (release, 0 if pre else 1, tail)


def _affected(version: str, entry: dict[str, Any]) -> bool:
    if version in (entry.get("versions") or []):
        return True
    key = version_key(version)
    for rng in entry.get("ranges") or []:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = rng.get("events") or []
        inside = False
        for event in events:
            if "introduced" in event:
                introduced = str(event["introduced"])
                if introduced == "0" or key >= version_key(introduced):
                    inside = True
            elif (
                "fixed" in event
                and inside
                and key >= version_key(str(event["fixed"]))
                or (
                    "last_affected" in event
                    and inside
                    and key > version_key(str(event["last_affected"]))
                )
            ):
                inside = False
        if inside:
            return True
    return False


# --- database ---


@lru_cache(maxsize=4)
def load_database(
    path: str, wanted: frozenset[str] | None = None
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Index advisories by (ecosystem, package). ``wanted`` (lower-cased names) limits parsing."""
    root = Path(path)
    records: list[dict[str, Any]] = []
    files = sorted(root.rglob("*.json*")) if root.is_dir() else [root]
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
            if f.suffix == ".jsonl":
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    if wanted is not None and not any(n in line.lower() for n in wanted):
                        continue
                    records.append(json.loads(line))
                continue
            data = json.loads(text)
        except (OSError, ValueError):
            continue
        if isinstance(data, list):
            records.extend(r for r in data if isinstance(r, dict))
        elif isinstance(data, dict) and isinstance(data.get("vulns"), list):
            records.extend(r for r in data["vulns"] if isinstance(r, dict))
        elif isinstance(data, dict):
            records.append(data)
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        if record.get("withdrawn"):
            continue
        for affected in record.get("affected") or []:
            pkg = affected.get("package") or {}
            ecosystem = str(pkg.get("ecosystem", "")).split(":")[0]
            name = str(pkg.get("name", ""))
            if ecosystem and name:
                key_name = _normalise_py(name) if ecosystem == "PyPI" else name.lower()
                index.setdefault((ecosystem, key_name), []).append(
                    {"record": record, "affected": affected}
                )
    return index


def _severity(record: dict[str, Any]) -> Severity:
    if str(record.get("id", "")).startswith("MAL-"):
        return Severity.CRITICAL  # known-malicious package
    label = str((record.get("database_specific") or {}).get("severity", "")).upper()
    return SEVERITY_BY_LABEL.get(label, Severity.MEDIUM)


def _fixed_versions(affected: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for rng in affected.get("ranges") or []:
        fixed.extend(str(e["fixed"]) for e in rng.get("events") or [] if "fixed" in e)
    return fixed


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


# --- scanner entry points ---


def known_vulnerabilities(ctx: ScannerContext) -> Iterator[ScannerHit]:
    scanner_root = ctx.settings.get("osv_scanner_root")
    if scanner_root:
        hits, status = osv_scanner_hits(Path(scanner_root), ctx.files)
        ctx.settings.setdefault("adapters", []).append(status)
        yield from hits
    db_path = ctx.settings.get("osv_db")
    if not db_path:
        return
    lockfiles = [sf for sf in ctx.files if is_lockfile(sf)]
    parsed = {sf.path: parse_lockfile(sf) for sf in lockfiles}
    wanted = frozenset(p.name.lower() for pkgs in parsed.values() for p in pkgs)
    if not wanted:
        return
    database = load_database(str(db_path), wanted)
    for sf in lockfiles:
        seen: set[tuple[str, str, str]] = set()
        for pkg in parsed[sf.path]:
            key = (
                pkg.ecosystem,
                _normalise_py(pkg.name) if pkg.ecosystem == "PyPI" else pkg.name.lower(),
            )
            for match in database.get(key, []):
                record, affected = match["record"], match["affected"]
                if (
                    not _affected(pkg.version, affected)
                    or (pkg.name, pkg.version, record["id"]) in seen
                ):
                    continue
                seen.add((pkg.name, pkg.version, record["id"]))
                aliases = [a for a in record.get("aliases") or [] if a.startswith("CVE-")]
                fixed = _fixed_versions(affected)
                line = _line_of(sf.text, pkg.needle)
                yield ScannerHit(
                    sf.path,
                    line,
                    line,
                    f"{pkg.name} {pkg.version} has a known vulnerability: {record['id']}"
                    + (f" ({', '.join(aliases)})" if aliases else "")
                    + (f" — {record['summary']}" if record.get("summary") else "")
                    + (f". Fixed in {', '.join(fixed)}." if fixed else "."),
                    snippet=f"{pkg.name}@{pkg.version} {record['id']}",
                    symbol=f"{sf.path}:{pkg.name}@{pkg.version}:{record['id']}",
                    confidence=Confidence.HIGH,
                    severity=_severity(record),
                )


def osv_scanner_hits(root: Path, files: list[SourceFile]) -> tuple[list[ScannerHit], AdapterStatus]:
    """Run the optional ``osv-scanner`` binary over the lockfiles and convert its JSON output."""
    binary = shutil.which("osv-scanner")
    if binary is None:
        return [], AdapterStatus("osv-scanner", "missing", "binary not found on PATH")
    hits: list[ScannerHit] = []
    for sf in (f for f in files if is_lockfile(f)):
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [binary, "--format", "json", "--lockfile", str(root / sf.path)],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            report = json.loads(done.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return hits, AdapterStatus("osv-scanner", "error", str(exc))
        for result in report.get("results") or []:
            for entry in result.get("packages") or []:
                pkg = entry.get("package") or {}
                for vuln in entry.get("vulnerabilities") or []:
                    name, version = str(pkg.get("name")), str(pkg.get("version"))
                    line = _line_of(sf.text, name)
                    hits.append(
                        ScannerHit(
                            sf.path,
                            line,
                            line,
                            f"{name} {version} has a known vulnerability: {vuln.get('id')}"
                            + (f" — {vuln['summary']}" if vuln.get("summary") else "")
                            + " (via osv-scanner).",
                            snippet=f"{name}@{version}",
                            symbol=f"{sf.path}:{name}@{version}:{vuln.get('id')}",
                            confidence=Confidence.HIGH,
                            severity=_severity(vuln),
                        )
                    )
    return hits, AdapterStatus("osv-scanner", "ok")
