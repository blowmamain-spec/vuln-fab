"""Offline SCA: lockfile parsers, version ordering, advisory matching, engine wiring (WP-8.2)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import SourceFile
from vulnfab.scanners import sca


def sf(path: str, text: str) -> SourceFile:
    return SourceFile(path, "json", text, "0" * 64)


def test_package_lock_v3_and_v1() -> None:
    v3 = json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
    )
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"b": {"version": "2.0.0"}}})
    assert [(p.name, p.version) for p in sca.parse_lockfile(sf("package-lock.json", v3))] == [
        ("a", "1.0.0")
    ]
    assert [(p.name, p.version) for p in sca.parse_lockfile(sf("package-lock.json", v1))] == [
        ("b", "2.0.0")
    ]


def test_composer_and_requirements_and_poetry() -> None:
    composer = json.dumps({"packages": [{"name": "Vendor/Pkg", "version": "v1.2.3"}]})
    pkgs = sca.parse_lockfile(sf("composer.lock", composer))
    assert pkgs and pkgs[0].version.lstrip("v") == "1.2.3"
    reqs = sca.parse_lockfile(sf("requirements.txt", "Django==4.2.0\n# c\nflask>=1\n-r x.txt\n"))
    assert [(p.name.lower(), p.version) for p in reqs] == [("django", "4.2.0")]
    poetry = sca.parse_lockfile(sf("poetry.lock", '[[package]]\nname = "x"\nversion = "1.0"\n'))
    assert [(p.name, p.version) for p in poetry] == [("x", "1.0")]


def test_broken_lockfile_is_ignored() -> None:
    assert sca.parse_lockfile(sf("package-lock.json", "{not json")) == []


def test_version_ordering() -> None:
    k = sca.version_key
    assert k("1.2.3") < k("1.10.0") < k("2.0.0")
    assert k("1.0.0rc1") < k("1.0.0")
    assert k("1.0") == k("1.0.0") or k("1.0") < k("1.0.1")


def test_affected_ranges_and_explicit_versions() -> None:
    rng = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]}
    assert sca._affected("1.2.0", rng)
    assert not sca._affected("1.5.0", rng)
    assert not sca._affected("0.9.0", rng)
    assert sca._affected("3.0.0", {"versions": ["3.0.0"]})


def _repo(tmp_path: Path, version: str) -> Path:
    repo = tmp_path / "r"
    repo.mkdir(parents=True)
    (repo / "requirements.txt").write_text(f"left-padder=={version}\n")
    return repo


DB = Path(__file__).parent.parent / "rules" / "sca-known-vuln" / "osv"


def test_engine_reports_and_is_deterministic(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "1.2.3")
    opts = ScanOptions(osv_db=DB)
    first = [f for f in scan(repo, opts).findings if f.rule_id == "sca-known-vuln"]
    second = [f for f in scan(repo, opts).findings if f.rule_id == "sca-known-vuln"]
    assert len(first) == 1 and "GHSA-test-0001" in first[0].message
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    fixed = scan(_repo(tmp_path / "x", "1.2.4"), opts)
    assert not [f for f in fixed.findings if f.rule_id == "sca-known-vuln"]


def test_coverage_note_without_database(tmp_path: Path) -> None:
    result = scan(_repo(tmp_path, "1.2.3"), ScanOptions())
    assert any("NOT checked for known vulnerabilities" in a for a in result.coverage.assumptions)


def test_osv_scanner_adapter_missing_and_fake(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repo = _repo(tmp_path, "1.2.3")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = scan(repo, ScanOptions(osv_scanner=True))
    assert [(a.name, a.status) for a in result.coverage.adapters] == [("osv-scanner", "missing")]

    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "osv-scanner"
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "left-padder", "version": "1.2.3"},
                        "vulnerabilities": [{"id": "OSV-FAKE-1", "summary": "bad"}],
                    }
                ]
            }
        ]
    }
    fake.write_text(f"#!/bin/sh\necho '{json.dumps(payload)}'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir))
    result = scan(repo, ScanOptions(osv_scanner=True))
    assert [a.status for a in result.coverage.adapters] == ["ok"]
    assert any("OSV-FAKE-1" in f.message for f in result.findings)
