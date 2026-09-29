import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnfab.cli import app
from vulnfab.core.config import ConfigError, ScanConfig, load_config
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence, Finding, Severity, Tier
from vulnfab.core.scoring import adjust, apply_supersedes, dedupe, sort_by_priority
from vulnfab.core.suppress import (
    BaselineError,
    PerFileIgnores,
    is_nosec,
    load_baseline,
    write_baseline,
)

FIXTURE = Path(__file__).resolve().parents[1] / "e2e" / "fixtures" / "eval_repo"


def F(
    rule: str = "py-eval",
    line: int = 3,
    end: int | None = None,
    tier: Tier | None = None,
    sev: Severity = Severity.HIGH,
    conf: Confidence = Confidence.MEDIUM,
    hops: int = 0,
    file: str = "a.py",
    snippet: str = "s",
) -> Finding:  # noqa: N802
    return Finding(rule, "t", (), None, sev, conf, tier, file, line, end or line, snippet,
                   unresolved_hops=hops, fingerprint=f"{rule}{line}")  # fmt: skip


# --- nosec ----------------------------------------------------------------------------------


def test_nosec_same_line_and_above() -> None:
    lines = ["a", "eval(x)  # nosec", "b", "# nosec", "eval(y)", "eval(z)"]
    assert is_nosec(F(line=2), lines)
    assert is_nosec(F(line=5), lines)  # comment-only line above
    assert not is_nosec(F(line=6), lines)
    assert not is_nosec(F(line=3), lines)


def test_nosec_with_rule_ids() -> None:
    lines = ["eval(x)  # nosec: py-other, py-eval", "eval(y)  # nosec: py-other"]
    assert is_nosec(F(line=1), lines)
    assert not is_nosec(F(line=2), lines)


def test_nosec_variants_and_multiline() -> None:
    assert is_nosec(F(line=1), ["eval(x) // NOSEC"])
    assert is_nosec(F(line=1, end=2), ["eval(a,", "  b)  # nosec"])
    assert not is_nosec(F(line=1), ["nosec is a word in code"])
    assert not is_nosec(F(line=2), ["x = 1  # nosec", "eval(y)"])  # trailing nosec on line above


def test_per_file_ignores() -> None:
    ign = PerFileIgnores({"scripts/**": ["py-eval"], "legacy/*.py": []})
    assert ign.ignores("scripts/a/b.py", "py-eval")
    assert not ign.ignores("scripts/a.py", "other-rule")
    assert ign.ignores("legacy/x.py", "anything")
    assert not ign.ignores("src/x.py", "py-eval")


# --- baseline -------------------------------------------------------------------------------


def test_baseline_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    assert write_baseline(path, [F(line=1), F(line=1), F(line=2)]) == 2
    assert load_baseline(path) == {"py-eval1", "py-eval2"}


@pytest.mark.parametrize(
    "content",
    ["not json", "[]", '{"schema_version": 9}', '{"schema_version": 1, "fingerprints": [1]}'],
)  # noqa: E501
def test_bad_baseline(tmp_path: Path, content: str) -> None:
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(BaselineError):
        load_baseline(path)
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "missing.json")


def test_baseline_hides_old_and_shows_new_after_line_shift(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    shutil.copytree(FIXTURE, repo)
    baseline = tmp_path / "base.json"
    first = scan(repo, ScanOptions(write_baseline=baseline))
    assert len(first.findings) == 3
    (repo / "app.py").write_text("# shift\n\n\n" + (repo / "app.py").read_text())
    second = scan(repo, ScanOptions(baseline=baseline))
    assert second.findings == [] and second.coverage.suppressed_baseline == 3
    (repo / "new.py").write_text("eval(user_input)\n")
    third = scan(repo, ScanOptions(baseline=baseline))
    assert [f.file for f in third.findings] == ["new.py"]


# --- config ---------------------------------------------------------------------------------


def _repo_with_config(tmp_path: Path, config: str) -> Path:
    repo = tmp_path / "r"
    shutil.copytree(FIXTURE, repo)
    (repo / ".vulnfab.yml").write_text(config)
    return repo


def test_config_disable_rule_and_exclude(tmp_path: Path) -> None:
    assert scan(_repo_with_config(tmp_path, "disable_rules: [py-eval]\n")).findings == []
    result = scan(_repo_with_config(tmp_path / "x", "exclude: ['app.py']\n"))
    assert {f.file for f in result.findings} == {"syntax_error.py"}


def test_config_per_file_ignore_and_severity_override(tmp_path: Path) -> None:
    repo = _repo_with_config(
        tmp_path,
        "per_file_ignores:\n  'app.py': [py-eval]\nseverity_overrides:\n  py-eval: low\n",
    )
    result = scan(repo)
    assert [f.file for f in result.findings] == ["syntax_error.py"]
    assert result.findings[0].severity is Severity.LOW
    assert result.coverage.suppressed_config == 2


def test_config_min_confidence_and_cli_override(tmp_path: Path) -> None:
    repo = _repo_with_config(tmp_path, "min_confidence: high\n")
    assert scan(repo).findings == []
    assert len(scan(repo, ScanOptions(min_confidence=Confidence.LOW)).findings) == 3


def test_nosec_in_scan(tmp_path: Path) -> None:
    repo = _repo_with_config(tmp_path, "{}\n")
    text = (repo / "app.py").read_text().replace("return eval(expr)", "return eval(expr)  # nosec")
    (repo / "app.py").write_text(text)
    result = scan(repo)
    assert result.coverage.suppressed_nosec == 1 and len(result.findings) == 2


@pytest.mark.parametrize(
    "content", ["unknown_key: 1", "min_confidence: enormous", "- a", "a: [", "max_file_kb: 0"]
)  # noqa: E501
def test_invalid_config(tmp_path: Path, content: str) -> None:
    (tmp_path / ".vulnfab.yml").write_text(content)
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_missing_config_is_default(tmp_path: Path) -> None:
    assert load_config(tmp_path) == ScanConfig()


def test_cli_reports_config_error_as_usage(tmp_path: Path) -> None:
    (tmp_path / ".vulnfab.yml").write_text("bogus: 1\n")
    (tmp_path / "a.py").write_text("x = 1\n")
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2 and "bogus" in result.output


def test_cli_baseline_flow(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    shutil.copytree(FIXTURE, repo)
    base = tmp_path / "b.json"
    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(repo), "--write-baseline", str(base)]).exit_code == 0
    out = runner.invoke(app, ["scan", str(repo), "--baseline", str(base), "--format", "json"])
    data = json.loads(out.output)
    assert data["findings"] == [] and data["coverage"]["suppressed_baseline"] == 3
    bad = runner.invoke(app, ["scan", str(repo), "--baseline", str(tmp_path / "nope.json")])
    assert bad.exit_code == 2


# --- scoring --------------------------------------------------------------------------------


def test_adjust_confidence_by_unresolved_hops_and_tiers() -> None:
    assert adjust(F(hops=1, conf=Confidence.HIGH)).confidence is Confidence.MEDIUM
    assert adjust(F(hops=5, conf=Confidence.HIGH)).confidence is Confidence.LOW
    assert adjust(F(tier="B", conf=Confidence.HIGH)).confidence is Confidence.MEDIUM
    c = adjust(F(tier="C"))
    assert c.severity is Severity.INFO and c.confidence is Confidence.LOW
    plain = F()
    assert adjust(plain) is plain


def test_dedupe_and_supersedes_and_sorting() -> None:
    a, dup = F(line=1), F(line=1)
    assert dedupe([a, dup, F(line=2)]) == [a, F(line=2)]
    specific, generic = F("sb-policy-anon-write", 5, 7), F("sb-policy-true", 6, 6)
    other_file = F("sb-policy-true", 6, 6, file="b.py")
    kept = apply_supersedes(
        [specific, generic, other_file], {"sb-policy-anon-write": ["sb-policy-true"]}
    )  # noqa: E501
    assert kept == [specific, other_file]
    low = F("x-a", 1, sev=Severity.LOW)
    crit = F("x-b", 2, sev=Severity.CRITICAL, conf=Confidence.LOW)
    high = F("x-c", 3, sev=Severity.HIGH, conf=Confidence.HIGH)
    assert [f.rule_id for f in sort_by_priority([low, crit, high])] == ["x-c", "x-b", "x-a"]
