"""Schema-rule check functions for Django ``settings.py`` (see rules/django/settings.yml)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from vulnfab.core.models import Confidence, ConfigDoc, TraceStep
from vulnfab.core.schemarules import CheckContext, SchemaHit
from vulnfab.plugins.django.pyconf import Dynamic, is_dynamic
from vulnfab.plugins.django.urlconf import PUBLIC_NAME

_DEV_FILE = re.compile(
    r"(?:^|[/_.-])(dev|develop|development|local|test|tests|testing|ci|debug|docker-dev)(?:[/_.-]|$)",
    re.I,
)
WEAK_HASHERS = (
    "MD5PasswordHasher",
    "UnsaltedMD5PasswordHasher",
    "SHA1PasswordHasher",
    "UnsaltedSHA1PasswordHasher",
    "CryptPasswordHasher",
)


def _is_dev(path: str) -> bool:
    return bool(_DEV_FILE.search(path))


def _value(doc: ConfigDoc, name: str) -> tuple[Any, int, bool]:
    """(value, line, certain). Uncertain when assigned conditionally or mutated later."""
    if name not in doc.data:
        return None, 1, False
    line = doc.lines.get((name,), 1)
    uncertain = name in doc.extras.get("conditional", []) or name in doc.extras.get("mutated", [])
    return doc.data[name], line, not uncertain


def _docs(ctx: CheckContext) -> Iterator[ConfigDoc]:
    yield from ctx.model.configs.values()


def _conf(path: str, base: Confidence = Confidence.MEDIUM) -> Confidence:
    return Confidence.LOW if _is_dev(path) else base


def debug_true(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        for name in ("DEBUG", "TEMPLATE_DEBUG"):
            value, line, certain = _value(doc, name)
            if value is True:
                yield SchemaHit(
                    doc.path,
                    line,
                    line,
                    f"{name} = True: on error Django shows source code, settings and SQL to the "
                    "visitor. It must be off in production."
                    + (
                        "" if certain else " (assignment is conditional; verify the deployed value)"
                    ),
                    symbol=f"{doc.path}:{name}",
                    confidence=Confidence.LOW
                    if _is_dev(doc.path) or not certain
                    else Confidence.MEDIUM,
                )


def secret_key_hardcoded(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        value, line, certain = _value(doc, "SECRET_KEY")
        if isinstance(value, str) and value and not is_dynamic(value):
            yield SchemaHit(
                doc.path,
                line,
                line,
                "SECRET_KEY is a literal in source control. Anyone with the repository can forge "
                "sessions and signed data"
                + (
                    " (and, with the pickle serializer, execute code)"
                    if _pickle_serializer(doc)
                    else ""
                )
                + ". Load it from the environment.",
                snippet="SECRET_KEY = '…'",
                symbol=f"{doc.path}:SECRET_KEY",
                confidence=Confidence.LOW if _is_dev(doc.path) else Confidence.HIGH,
            )


def allowed_hosts_wildcard(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        value, line, _ = _value(doc, "ALLOWED_HOSTS")
        if isinstance(value, (list, tuple)) and any(
            v == "*" for v in value if not isinstance(v, Dynamic)
        ):
            yield SchemaHit(
                doc.path,
                line,
                line,
                "ALLOWED_HOSTS contains '*': Host-header attacks (password-reset poisoning, cache "
                "poisoning) are not blocked. List the real host names.",
                symbol=f"{doc.path}:ALLOWED_HOSTS",
                confidence=_conf(doc.path),
            )


def weak_password_hasher(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        value, line, _ = _value(doc, "PASSWORD_HASHERS")
        if not isinstance(value, (list, tuple)) or not value:
            continue
        literals = [v for v in value if isinstance(v, str)]
        weak = [v for v in literals if v.rsplit(".", 1)[-1] in WEAK_HASHERS]
        if not weak:
            continue
        first_weak = literals and literals[0].rsplit(".", 1)[-1] in WEAK_HASHERS
        yield SchemaHit(
            doc.path,
            line,
            line,
            f"PASSWORD_HASHERS uses {', '.join(w.rsplit('.', 1)[-1] for w in weak)}: fast, "
            + (
                "and it is the primary hasher, so every new password is stored weakly."
                if first_weak
                else "unsalted or broken hashes are still accepted for existing users."
            )
            + " Use PBKDF2/Argon2/bcrypt first.",
            symbol=f"{doc.path}:PASSWORD_HASHERS",
            confidence=_conf(doc.path, Confidence.HIGH if first_weak else Confidence.MEDIUM),
        )


def _pickle_serializer(doc: ConfigDoc) -> bool:
    value = doc.data.get("SESSION_SERIALIZER")
    return isinstance(value, str) and "PickleSerializer" in value


def pickle_session_serializer(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        if _pickle_serializer(doc):
            _, line, _ = _value(doc, "SESSION_SERIALIZER")
            engine = doc.data.get("SESSION_ENGINE")
            signed = isinstance(engine, str) and "signed_cookies" in engine
            yield SchemaHit(
                doc.path,
                line,
                line,
                "SESSION_SERIALIZER uses pickle: whoever can forge a session cookie (or a session "
                "row) gets remote code execution."
                + (
                    " With signed_cookies sessions the SECRET_KEY alone is enough."
                    if signed
                    else ""
                ),
                symbol=f"{doc.path}:SESSION_SERIALIZER",
                confidence=_conf(doc.path, Confidence.HIGH),
            )


def session_cookie_httponly_off(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        for name in ("SESSION_COOKIE_HTTPONLY", "CSRF_COOKIE_HTTPONLY"):
            value, line, _ = _value(doc, name)
            if value is False and name == "SESSION_COOKIE_HTTPONLY":
                yield SchemaHit(
                    doc.path,
                    line,
                    line,
                    "SESSION_COOKIE_HTTPONLY = False lets JavaScript read the session cookie, so "
                    "any XSS becomes session theft.",
                    symbol=f"{doc.path}:{name}",
                    confidence=_conf(doc.path),
                )


def cookie_secure_off(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        debug, _, _ = _value(doc, "DEBUG")
        for name in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE"):
            value, line, _ = _value(doc, name)
            if value is False:
                yield SchemaHit(
                    doc.path,
                    line,
                    line,
                    f"{name} = False: the cookie is also sent over plain HTTP and can be sniffed.",
                    symbol=f"{doc.path}:{name}",
                    confidence=Confidence.LOW
                    if debug is True or _is_dev(doc.path)
                    else Confidence.MEDIUM,
                )


def csrf_middleware_missing(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        for name in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
            value, line, certain = _value(doc, name)
            if not isinstance(value, (list, tuple)) or not certain or is_dynamic(value):
                continue
            if any(isinstance(v, str) and v.endswith("CsrfViewMiddleware") for v in value):
                continue
            yield SchemaHit(
                doc.path,
                line,
                line,
                f"{name} does not include CsrfViewMiddleware: state-changing views accept "
                "cross-site requests.",
                symbol=f"{doc.path}:{name}",
                confidence=_conf(doc.path, Confidence.HIGH),
            )


def clickjacking_protection_missing(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        for name in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
            value, line, certain = _value(doc, name)
            if isinstance(value, (list, tuple)) and certain and not is_dynamic(value):
                xfo = doc.data.get("X_FRAME_OPTIONS")
                has = any(
                    isinstance(v, str) and v.endswith("XFrameOptionsMiddleware") for v in value
                )
                if not has and not (isinstance(xfo, str) and xfo.upper() in ("DENY", "SAMEORIGIN")):
                    yield SchemaHit(
                        doc.path,
                        line,
                        line,
                        f"{name} lacks XFrameOptionsMiddleware: pages can be framed by other sites "
                        "(clickjacking).",
                        symbol=f"{doc.path}:{name}",
                        confidence=Confidence.LOW,
                    )


def password_validators_missing(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        if "INSTALLED_APPS" not in doc.data:
            continue
        value, line, certain = _value(doc, "AUTH_PASSWORD_VALIDATORS")
        if (value is None and "AUTH_PASSWORD_VALIDATORS" not in doc.data) or value == []:
            line = line if value == [] else doc.lines.get(("INSTALLED_APPS",), 1)
            yield SchemaHit(
                doc.path,
                line,
                line,
                "AUTH_PASSWORD_VALIDATORS is empty or missing: any password, however weak, is "
                "accepted.",
                symbol=f"{doc.path}:AUTH_PASSWORD_VALIDATORS",
                confidence=Confidence.LOW,
            )


def view_no_auth(ctx: CheckContext) -> Iterator[SchemaHit]:
    """URL-mapped views that neither require login nor check the user, yet touch data."""
    seen: set[tuple[str, str]] = set()
    for entry in ctx.entrypoints:
        if entry.auth is None or entry.auth.required is not False:
            continue
        if PUBLIC_NAME.match(entry.handler) or (entry.file, entry.handler) in seen:
            continue
        seen.add((entry.file, entry.handler))
        if "writes" in entry.traits:
            what, confidence = "changes data", Confidence.MEDIUM
        elif "reads-data" in entry.traits and entry.params:
            what, confidence = "returns data selected by a URL parameter", Confidence.MEDIUM
        else:
            continue
        yield SchemaHit(
            entry.file,
            entry.line,
            entry.line,
            f"View {entry.handler} (route {entry.route or '?'}) {what} but has no login/permission "
            "decorator or mixin and does not inspect request.user.",
            trace=(TraceStep(entry.route_file, entry.route_line, "call", f"route {entry.route}"),)
            if entry.route_file
            else (),
            symbol=f"{entry.file}:{entry.handler}",
            confidence=confidence,
        )


def csrf_exempt_view(ctx: CheckContext) -> Iterator[SchemaHit]:
    """Views that opt out of CSRF protection while changing data."""
    seen: set[tuple[str, str]] = set()
    for entry in ctx.entrypoints:
        if "csrf-exempt" not in entry.traits or (entry.file, entry.handler) in seen:
            continue
        seen.add((entry.file, entry.handler))
        writes = "writes" in entry.traits
        yield SchemaHit(
            entry.file,
            entry.line,
            entry.line,
            f"View {entry.handler} is @csrf_exempt"
            + (" and changes data" if writes else "")
            + ": another site can make a logged-in user's browser submit requests to it.",
            trace=(TraceStep(entry.route_file, entry.route_line, "call", f"route {entry.route}"),)
            if entry.route_file
            else (),
            symbol=f"{entry.file}:{entry.handler}",
            confidence=Confidence.MEDIUM if writes else Confidence.LOW,
        )


def database_password_literal(ctx: CheckContext) -> Iterator[SchemaHit]:
    for doc in _docs(ctx):
        databases = doc.data.get("DATABASES")
        if not isinstance(databases, dict):
            continue
        for alias, cfg in databases.items():
            password = cfg.get("PASSWORD") if isinstance(cfg, dict) else None
            if isinstance(password, str) and password and not _is_dev(doc.path):
                line = doc.lines.get(("DATABASES",), 1)
                yield SchemaHit(
                    doc.path,
                    line,
                    line,
                    f"DATABASES['{alias}'] contains a literal PASSWORD. Credentials in the "
                    "repository are exposed to everyone who can read it.",
                    snippet="'PASSWORD': '…'",
                    symbol=f"{doc.path}:DATABASES:{alias}",
                    confidence=Confidence.MEDIUM,
                )
