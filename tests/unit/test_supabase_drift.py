from pathlib import Path

from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence

MIGRATION = """
create table public.a (id int);
alter table public.a enable row level security;
"""

DUMP = """
CREATE TABLE public.a (id integer);
CREATE TABLE public.dashboard_made (id integer);
ALTER TABLE public.dashboard_made ENABLE ROW LEVEL SECURITY;
"""


def _repo(tmp_path: Path) -> Path:
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "20240101000000_a.sql").write_text(MIGRATION)
    return tmp_path


def test_drift_reports_rls_and_dashboard_tables(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r")
    dump = tmp_path / "live.sql"
    dump.write_text(DUMP)
    result = scan(repo, ScanOptions(min_confidence=Confidence.LOW, schema_dump=dump))
    drift = [f for f in result.findings if f.rule_id == "sb-schema-drift"]
    messages = sorted(f.message for f in drift)
    assert len(drift) == 2
    assert any("disabled in the live database" in m for m in messages)
    dash = next(f for f in drift if f.file == "live.sql")
    assert "dashboard" in dash.message and "public.dashboard_made" in dash.message
    assert any("Schema drift checked" in a for a in result.coverage.assumptions)
    assert not any("migrations only" in a for a in result.coverage.assumptions)


def test_no_dump_means_no_drift_findings_and_notes_the_assumption(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r")
    result = scan(repo, ScanOptions(min_confidence=Confidence.LOW))
    assert [f for f in result.findings if f.rule_id == "sb-schema-drift"] == []
    assert any("migrations only" in a for a in result.coverage.assumptions)


def test_cli_schema_dump_option(tmp_path: Path) -> None:
    import json

    from typer.testing import CliRunner

    from vulnfab.cli import app

    repo = _repo(tmp_path / "r")
    dump = tmp_path / "live.sql"
    dump.write_text(DUMP)
    runner = CliRunner()
    ok = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--schema-dump",
            str(dump),
            "--min-confidence",
            "low",
            "--format",
            "json",
        ],
    )
    assert ok.exit_code == 0
    assert any(f["rule_id"] == "sb-schema-drift" for f in json.loads(ok.output)["findings"])
    missing = runner.invoke(app, ["scan", str(repo), "--schema-dump", str(tmp_path / "nope.sql")])
    assert missing.exit_code == 2
