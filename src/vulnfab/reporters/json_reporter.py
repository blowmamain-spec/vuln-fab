from __future__ import annotations

import json

from vulnfab.core.report import ScanResult, to_json_dict


def render(result: ScanResult) -> str:
    return json.dumps(to_json_dict(result), indent=2, ensure_ascii=False) + "\n"
