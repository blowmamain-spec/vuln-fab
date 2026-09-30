"""``vulnfab osv update`` against a local mirror (no internet in tests)."""

from __future__ import annotations

import functools
import http.server
import io
import json
import threading
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from vulnfab.cli import app
from vulnfab.core.engine import ScanOptions, scan

RECORD = {
    "id": "GHSA-mirror-0001",
    "summary": "x" * 10,
    "details": "dropped",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "left-padder"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
            "ecosystem_specific": {"dropped": True},
        }
    ],
}


def make_mirror(root: Path) -> None:
    (root / "PyPI").mkdir(parents=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-mirror-0001.json", json.dumps(RECORD))
        z.writestr("broken.json", "{nope")
    (root / "PyPI" / "all.zip").write_bytes(buf.getvalue())


def serve(root: Path):  # type: ignore[no-untyped-def]
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_update_then_scan_offline(tmp_path: Path) -> None:
    mirror = tmp_path / "mirror"
    make_mirror(mirror)
    server = serve(mirror)
    try:
        db = tmp_path / "db"
        url = f"http://127.0.0.1:{server.server_address[1]}"
        result = CliRunner().invoke(
            app, ["osv", "update", str(db), "-e", "PyPI", "--base-url", url]
        )
    finally:
        server.shutdown()
    assert result.exit_code == 0, result.output
    assert "PyPI: 1 advisories" in result.output
    stored = (db / "PyPI.jsonl").read_text().strip().splitlines()
    assert len(stored) == 1 and "details" not in stored[0] and "ecosystem_specific" not in stored[0]
    assert (db / "osv-meta.json").is_file()

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("Left_Padder==1.0\n")
    found = scan(repo, ScanOptions(osv_db=db))
    assert any(f.rule_id == "sca-known-vuln" for f in found.findings)


def test_failed_download_keeps_previous_data(tmp_path: Path) -> None:
    db = tmp_path / "db"
    db.mkdir()
    (db / "PyPI.jsonl").write_text("keep\n")
    result = CliRunner().invoke(
        app, ["osv", "update", str(db), "-e", "PyPI", "--base-url", "http://127.0.0.1:9"]
    )
    assert result.exit_code == 2
    assert (db / "PyPI.jsonl").read_text() == "keep\n"
