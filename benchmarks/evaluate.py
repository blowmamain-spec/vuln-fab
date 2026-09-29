"""Evaluate scan output against ground truth.

    python benchmarks/evaluate.py --target supabase-vuln --findings out.json [--out report.md]

Exit code 1 if there are unreviewed findings (unless --allow-unreviewed), or a gate fails.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

from vulnfab.evaluation import (
    EvaluationError,
    evaluate,
    format_markdown,
    load_findings,
    load_truth,
    load_verdicts,
)

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--findings", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--allow-unreviewed", action="store_true")
    ap.add_argument("--min-precision", type=float)
    ap.add_argument("--min-recall", type=float)
    ap.add_argument("--max-decoy-hits", type=int)
    ap.add_argument(
        "--classes",
        help="comma separated finding classes to evaluate (default: classes present in the truth)",
    )
    args = ap.parse_args()
    try:
        target, truth = load_truth(HERE / "truth" / f"{args.target}.json")
        verdicts = load_verdicts(HERE / "verdicts" / f"{args.target}.json")
        findings = load_findings(args.findings)
        excludes = json.loads((HERE / "truth" / f"{args.target}.json").read_text()).get(
            "exclude", []
        )
        classes = set(args.classes.split(",")) if args.classes else {t.cls for t in truth}
        kept = [
            f
            for f in findings
            if f.cls in classes and not any(fnmatch.fnmatch(f.file, g) for g in excludes)
        ]
        print(
            f"(evaluated {len(kept)} of {len(findings)} findings: classes={sorted(classes)}, "
            f"excluded paths={excludes})",
            file=sys.stderr,
        )
        report = evaluate(target, truth, kept, verdicts)
    except (EvaluationError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    text = format_markdown(report)
    if args.out:
        args.out.write_text(text)
    print(text)
    failed = False
    if report.unreviewed and not args.allow_unreviewed:
        print(f"FAIL: {len(report.unreviewed)} findings without verdict", file=sys.stderr)
        failed = True
    o = report.overall
    if args.min_precision is not None and (o.precision or 0) < args.min_precision:
        print(f"FAIL: precision {o.precision} < {args.min_precision}", file=sys.stderr)
        failed = True
    if args.min_recall is not None and (o.recall or 0) < args.min_recall:
        print(f"FAIL: recall {o.recall} < {args.min_recall}", file=sys.stderr)
        failed = True
    if args.max_decoy_hits is not None and len(report.decoy_hits) > args.max_decoy_hits:
        print(f"FAIL: {len(report.decoy_hits)} decoy hits > {args.max_decoy_hits}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
