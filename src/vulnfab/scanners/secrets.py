"""Built-in secret detection: provider patterns plus a guarded generic assignment heuristic."""

from __future__ import annotations

import base64
import json
import math
import re
from collections.abc import Iterator
from typing import Any

from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.scannerrules import ScannerContext, ScannerHit

# name, regex, description; matched anywhere on a line
PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    (
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}\b")

ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<name>[A-Za-z0-9_.\-]*
        (?:secret|passwd|password|token|api[_-]?key|apikey|private[_-]?key|auth[_-]?key|credential)
        [A-Za-z0-9_.\-]*)
    \s*(?::|=|=>)\s*
    (?P<quote>['"])(?P<value>[^'"\n]{12,}?)(?P=quote)
    """
)
ENV_LINE_RE = re.compile(
    r"""(?ix)^\s*(?:export\s+)?
    (?P<name>[A-Za-z0-9_]*(?:secret|passwd|password|token|api_?key|private_?key|credential)[A-Za-z0-9_]*)
    \s*=\s*(?P<value>[^\s#'"][^\s#]{11,}|"[^"\n]{12,}"|'[^'\n]{12,}')"""
)
PLACEHOLDER_WORDS = (
    "your", "example", "placeholder", "changeme", "change_me", "change-me", "xxx", "dummy",
    "sample", "fake", "todo", "redacted", "insert", "replace", "enter", "secret_here",
    "<", ">", "${", "{{", "process.env", "os.environ", "getenv", "env(", "config(",
    "encrypted:",  # dotenvx / sops style encrypted values
)  # fmt: skip
SKIP_FILE_SUFFIXES = (".min.js", ".lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
MIN_ENTROPY = 3.2


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def looks_like_secret_value(value: str) -> bool:
    lowered = value.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return False
    if re.search(r"\s", value) or value.startswith(("http://", "https://", "/", "./", "../")):
        return False
    if len(set(value)) < 6:
        return False
    if re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)+", value):
        return False  # kebab/snake-case words are names, not credentials
    classes = sum(
        bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    return classes >= 2 and shannon_entropy(value) >= MIN_ENTROPY


def _jwt_role(payload_b64: str) -> str | None:
    """Role of a JWT payload, or ``None`` (also for the public Supabase local-dev demo key)."""
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        data: Any = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("iss") == "supabase-demo":
        return None  # the demo keys ship with the Supabase CLI and are public by design
    return str(data.get("role"))


def scan_file(sf: SourceFile) -> Iterator[tuple[int, str, str, Confidence | None]]:
    """Yield ``(line, what, snippet, confidence)`` for each secret candidate."""
    if sf.path.endswith(SKIP_FILE_SUFFIXES):
        return
    for number, line in enumerate(sf.text.split("\n"), start=1):
        if len(line) > 2000:
            continue
        reported = False
        for label, pattern in PROVIDER_PATTERNS:
            if pattern.search(line):
                yield number, label, line.strip(), Confidence.HIGH
                reported = True
                break
        if reported:
            continue
        jwt = JWT_RE.search(line)
        if jwt and _jwt_role(jwt.group(1)) == "service_role":
            yield number, "Supabase service_role JWT", line.strip(), Confidence.HIGH
            continue
        match = ENV_LINE_RE.match(line) if sf.language == "env" else None
        match = match or ASSIGNMENT_RE.search(line)
        if match and looks_like_secret_value(match.group("value").strip("'\"")):
            yield number, f"hard-coded value for {match.group('name')!r}", line.strip(), None


def scan(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        for line, what, snippet, confidence in scan_file(sf):
            yield ScannerHit(
                sf.path,
                line,
                line,
                f"Possible secret committed to source control: {what}.",
                snippet=_redact(snippet),
                symbol=f"{sf.path}:{what}",
                confidence=confidence,
            )


def _redact(text: str) -> str:
    """Never echo the full secret back into reports."""
    return re.sub(
        r"(['\"=:\s])([A-Za-z0-9_\-+/.=]{12,})(['\"]?)",
        lambda m: (
            f"{m.group(1)}{m.group(2)[:4]}…{m.group(2)[-2:]}{m.group(3)}"
            if len(m.group(2)) >= 16 and shannon_entropy(m.group(2)) >= MIN_ENTROPY
            else m.group(0)
        ),
        text,
    )
