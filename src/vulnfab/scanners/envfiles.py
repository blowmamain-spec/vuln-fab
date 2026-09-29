"""Scanner for ``.env`` files: privileged keys exposed through public build-time prefixes."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.scannerrules import ScannerContext, ScannerHit

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)"
SERVICE_ROLE_ENV = re.compile(
    rf"^\s*(?:export\s+)?({PUBLIC_PREFIX}_[A-Z0-9_]*(?:SERVICE_ROLE|SERVICE_KEY)[A-Z0-9_]*)\s*=\s*(\S.*)$"
)


def service_role_in_public_env(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        for number, line in enumerate(sf.text.split("\n"), start=1):
            match = SERVICE_ROLE_ENV.match(line)
            if match and match.group(2).strip("'\" "):
                name = match.group(1)
                yield ScannerHit(
                    sf.path,
                    number,
                    number,
                    f"{name} is bundled into the client build: the Supabase service_role key "
                    "bypasses Row Level Security and must stay server-side.",
                    snippet=f"{name}=…",
                    symbol=f"{sf.path}:{name}",
                )
