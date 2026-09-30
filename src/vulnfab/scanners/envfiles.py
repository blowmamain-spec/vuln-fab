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


PUBLIC_SECRET_ENV = re.compile(
    rf"^\s*(?:export\s+)?({PUBLIC_PREFIX}_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|PASSWD|ADMIN_KEY)"
    r"[A-Z0-9_]*)\s*=\s*(\S.*)$"
)
_PLACEHOLDER = re.compile(r"(?i)^(?:your[_-].*|changeme|<.*>|x+|\*+|todo|example.*|)$")


def secret_in_public_env(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        for number, line in enumerate(sf.text.split("\n"), start=1):
            match = PUBLIC_SECRET_ENV.match(line)
            if not match:
                continue
            value = re.split(r"\s+#", match.group(2))[0].strip("'\" ")
            if _PLACEHOLDER.match(value):
                continue
            name = match.group(1)
            yield ScannerHit(
                sf.path,
                number,
                number,
                f"{name} has a secret-looking name but a public build prefix: its value is "
                "embedded in the client bundle and visible to every visitor.",
                snippet=f"{name}=…",
                symbol=f"{sf.path}:{name}",
            )
