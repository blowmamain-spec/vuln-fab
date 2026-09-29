"""Run every benchmark target and write ``benchmarks/results/latest.md`` (WP-9.1).

    python benchmarks/run_all.py [--offline] [--only NAME ...]

Targets live in ``benchmarks/targets`` (fetched with ``fetch_targets.sh``) or ``benchmarks/labs``.
Unlabelled findings need a verdict (``benchmarks/verdicts/<target>.json``); they are listed in the
report and make the run fail so nothing is silently counted.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from vulnfab import __version__
from vulnfab.core.engine import ScanOptions, scan
from vulnfab.core.models import Confidence
from vulnfab.core.report import to_json_dict
from vulnfab.evaluation import (
    Counts,
    Report,
    evaluate,
    load_findings,
    load_truth,
    load_verdicts,
)

HERE = Path(__file__).resolve().parent
# name -> (directory, min confidence used for the gate)
TARGETS: dict[str, tuple[Path, Confidence]] = {
    "supabase-vuln": (HERE / "labs" / "supabase-vuln", Confidence.LOW),
    "django-vuln": (HERE / "labs" / "django-vuln", Confidence.MEDIUM),
    "laravel-vuln": (HERE / "labs" / "laravel-vuln", Confidence.MEDIUM),
    "nodegoat": (HERE / "targets" / "nodegoat", Confidence.MEDIUM),
    "juice-shop": (HERE / "targets" / "juice-shop", Confidence.MEDIUM),
    "dvwa": (HERE / "targets" / "dvwa", Confidence.MEDIUM),
    "django-nv": (HERE / "targets" / "django-nv", Confidence.MEDIUM),
}
PRECISION_FLOOR = {"critical": 0.90, "high": 0.80, "medium": 0.70}


@dataclass
class Row:
    name: str
    seconds: float
    findings: int
    report: Report
    severities: dict[str, str]


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def run_target(name: str, directory: Path, min_conf: Confidence) -> Row:
    start = time.perf_counter()
    result = scan(directory, ScanOptions(min_confidence=min_conf, use_cache=False))
    seconds = time.perf_counter() - start
    document = to_json_dict(result)
    tmp = HERE / "results" / f".{name}.findings.json"
    tmp.write_text(json.dumps(document))
    try:
        target, truth = load_truth(HERE / "truth" / f"{name}.json")
        raw = json.loads((HERE / "truth" / f"{name}.json").read_text())
        excludes = raw.get("exclude", [])
        import fnmatch

        classes = {t.cls for t in truth}
        findings = [
            f
            for f in load_findings(tmp)
            if f.cls in classes and not any(fnmatch.fnmatch(f.file, g) for g in excludes)
        ]
        report = evaluate(
            target, truth, findings, load_verdicts(HERE / "verdicts" / f"{name}.json")
        )
    finally:
        tmp.unlink(missing_ok=True)
    severities = {f["rule_id"]: f["severity"] for f in document["findings"]}
    return Row(name, seconds, len(result.findings), report, severities)


def render(rows: list[Row]) -> str:
    lines = [
        "# Hasil benchmark terbaru",
        "",
        f"Dibuat oleh `benchmarks/run_all.py` · vulnfab {__version__} · {date.today().isoformat()}.",
        "Label lab ditulis oleh pembuat rule (gerbang regresi, bukan bukti akurasi); label DVWA,",
        "django.nV, Juice Shop, NodeGoat dan catatan bias ada di `m2.md` / `m3.md`.",
        "",
        "## Per target",
        "",
        "| Target | Waktu (dtk) | Temuan | Recall | Precision | Decoy terpicu | Belum di-review |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        o = r.report.overall
        lines.append(
            f"| {r.name} | {r.seconds:.1f} | {r.findings} | {pct(o.recall)} "
            f"({o.labels_hit}/{o.labels_total}) | {pct(o.precision)} (TP {o.tp}, FP {o.fp}) | "
            f"{len(r.report.decoy_hits)} | {len(r.report.unreviewed)} |"
        )
    totals: dict[str, Counts] = {}
    severity: dict[str, str] = {}
    for r in rows:
        severity.update(r.severities)
        for rule, c in r.report.by_rule.items():
            t = totals.setdefault(rule, Counts())
            t.tp += c.tp
            t.fp += c.fp
    lines += [
        "",
        "## Per rule (gabungan semua target, hanya kelas yang berlabel)",
        "",
        "| Rule | Severity | TP | FP | Precision | Ambang | Status |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for rule in sorted(totals):
        c = totals[rule]
        sev = severity.get(rule, "")
        floor = PRECISION_FLOOR.get(sev)
        low = floor is not None and c.precision is not None and c.precision < floor
        lines.append(
            f"| {rule} | {sev} | {c.tp} | {c.fp} | {pct(c.precision)} | "
            f"{pct(floor) if floor else '—'} | {'**di bawah ambang**' if low else 'ok'} |"
        )
    problems = [
        f"- {r.name}: {len(r.report.unreviewed)} temuan tanpa verdict"
        for r in rows
        if r.report.unreviewed
    ]
    if problems:
        lines += ["", "## Perlu perhatian", *problems]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="skip targets that are not fetched")
    parser.add_argument("--only", nargs="*", help="run only these targets")
    args = parser.parse_args()
    if not args.offline:
        missing = [n for n, (d, _) in TARGETS.items() if not d.exists() and "targets" in d.parts]
        if missing:
            subprocess.run(["bash", str(HERE / "fetch_targets.sh")], check=False)  # noqa: S603, S607
    rows: list[Row] = []
    (HERE / "results").mkdir(exist_ok=True)
    for name, (directory, min_conf) in TARGETS.items():
        if args.only and name not in args.only:
            continue
        if not directory.exists():
            print(f"skip {name}: {directory} is missing (run fetch_targets.sh)", file=sys.stderr)
            continue
        print(f"== {name}", file=sys.stderr)
        rows.append(run_target(name, directory, min_conf))
    (HERE / "results" / "latest.md").write_text(render(rows))
    print((HERE / "results" / "latest.md").read_text())
    return 1 if any(r.report.unreviewed for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
