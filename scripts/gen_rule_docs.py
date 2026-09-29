"""Generate docs/rules.md from the rule packs.

python scripts/gen_rule_docs.py          # write the file
python scripts/gen_rule_docs.py --check  # exit 1 if it is out of date (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnfab import __version__
from vulnfab.core.ruledocs import reference_markdown
from vulnfab.core.rules import load_rules
from vulnfab.plugins import registry

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "rules.md"


def render() -> str:
    packs = [p for plugin in registry.discover() for p in plugin.rule_packs() if p.exists()]
    # the version is deliberately left out of the diff-sensitive text: rules define the content
    return reference_markdown(load_rules(packs), __version__.rsplit(".", 1)[0] + ".x")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != text:
            print(f"{TARGET} is out of date; run scripts/gen_rule_docs.py", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
