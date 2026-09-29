"""Text scanners for Laravel configuration: .env, config/app.php, CSRF exceptions, seeders."""

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence
from vulnfab.core.scannerrules import ScannerContext, ScannerHit

_DEV_ENV = re.compile(
    r"\.env\.(example|sample|dist|local|dev|development|testing|test|ci)$|\.example$"
)
_WEAK_PASSWORD = re.compile(
    r"['\"](password|secret|12345678?|123456789|admin|admin123|changeme|qwerty|letmein)['\"]", re.I
)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def app_debug(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        name = _basename(sf.path)
        if sf.language == "env" and name.startswith(".env"):
            for number, text in enumerate(sf.text.split("\n"), start=1):
                m = re.match(r"^\s*APP_DEBUG\s*=\s*['\"]?(true|1|on)['\"]?\s*(#.*)?$", text, re.I)
                if m:
                    production = "prod" in name.lower()
                    dev = bool(_DEV_ENV.search(name))
                    yield ScannerHit(
                        sf.path,
                        number,
                        number,
                        "APP_DEBUG=true makes Laravel show stack traces, environment values and "
                        "database credentials to visitors on errors.",
                        snippet="APP_DEBUG=true",
                        symbol=f"{sf.path}:APP_DEBUG",
                        confidence=Confidence.HIGH
                        if production
                        else (Confidence.LOW if dev else Confidence.MEDIUM),
                    )
        elif sf.language == "php" and sf.path.endswith("config/app.php"):
            for number, text in enumerate(sf.text.split("\n"), start=1):
                if re.match(r"^\s*['\"]debug['\"]\s*=>\s*true\s*,", text):
                    yield ScannerHit(
                        sf.path,
                        number,
                        number,
                        "config/app.php sets 'debug' => true without reading APP_DEBUG.",
                        snippet=text.strip(),
                        symbol=f"{sf.path}:debug",
                        confidence=Confidence.MEDIUM,
                    )


def app_key_committed(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        name = _basename(sf.path)
        if sf.language != "env" or not name.startswith(".env") or _DEV_ENV.search(name):
            continue
        for number, text in enumerate(sf.text.split("\n"), start=1):
            m = re.match(r"^\s*APP_KEY\s*=\s*(\S+)", text)
            if m and m.group(1).strip("'\"") not in ("", "null", "changeme"):
                yield ScannerHit(
                    sf.path,
                    number,
                    number,
                    "APP_KEY is present in a committed env file. It signs and encrypts cookies "
                    "and sessions; anyone with the repository can forge them. Rotate it and "
                    "keep it out of version control.",
                    snippet="APP_KEY=…",
                    symbol=f"{sf.path}:APP_KEY",
                    confidence=Confidence.MEDIUM,
                )


def csrf_except_wildcard(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if not sf.path.endswith("VerifyCsrfToken.php"):
            continue
        for m in re.finditer(r"\$except\s*=\s*\[(.*?)\]\s*;", sf.text, re.DOTALL):
            if re.search(r"['\"]\*['\"]", m.group(1)):
                line = sf.text.count("\n", 0, m.start()) + 1
                yield ScannerHit(
                    sf.path,
                    line,
                    line,
                    "VerifyCsrfToken::$except contains '*': CSRF verification is switched off for "
                    "every route.",
                    snippet="$except = ['*']",
                    symbol=f"{sf.path}:except",
                    confidence=Confidence.HIGH,
                )


def seeder_weak_password(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if "database/seeders/" not in sf.path and "database/factories/" not in sf.path:
            continue
        guarded = "environment(" in sf.text or "app()->isProduction" in sf.text
        for number, text in enumerate(sf.text.split("\n"), start=1):
            if (
                re.search(r"(Hash::make|bcrypt)\(\s*" + _WEAK_PASSWORD.pattern, text, re.I)
                and "password" in text.lower()
            ):
                if "factories/" in sf.path:
                    continue  # factories are test data
                yield ScannerHit(
                    sf.path,
                    number,
                    number,
                    "A seeder creates an account with a well-known password. If the seeder runs "
                    "in production this is a default credential.",
                    snippet=text.strip()[:100],
                    symbol=f"{sf.path}:{number}",
                    confidence=Confidence.LOW if guarded else Confidence.MEDIUM,
                )
