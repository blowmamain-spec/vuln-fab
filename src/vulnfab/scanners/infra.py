"""Scanners for deployment configuration: Dockerfile, docker-compose, nginx, env debug flags."""
# ruff: noqa: E501

from __future__ import annotations

import re
from collections.abc import Iterator

from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.scannerrules import ScannerContext, ScannerHit
from vulnfab.scanners.secrets import looks_like_secret_value

SECRET_NAME = re.compile(
    r"(secret|passw(?:or)?d|passwd|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)",
    re.I,
)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


def _hit(
    sf: SourceFile, line: int, message: str, snippet: str, conf: Confidence | None = None
) -> ScannerHit:
    return ScannerHit(
        sf.path,
        line,
        line,
        message,
        snippet=snippet.strip()[:120],
        symbol=f"{sf.path}:{line}",
        confidence=conf,
    )


# --- Dockerfile ------------------------------------------------------------------------------------


def _instructions(sf: SourceFile) -> list[tuple[int, str, str]]:
    """(first line, INSTRUCTION, arguments) with backslash continuations joined."""
    out: list[tuple[int, str, str]] = []
    buffer: list[str] = []
    start = 0
    for number, raw in enumerate(sf.text.split("\n"), start=1):
        text = raw.strip()
        if not buffer and (not text or text.startswith("#")):
            continue
        if not buffer:
            start = number
        continued = text.endswith("\\")
        buffer.append(text.rstrip("\\").strip())
        if not continued:
            joined = " ".join(b for b in buffer if b)
            keyword, _, rest = joined.partition(" ")
            out.append((start, keyword.upper(), rest.strip()))
            buffer = []
    return out


def docker_runs_as_root(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        instructions = _instructions(sf)
        froms = [n for n, kw, _ in instructions if kw == "FROM"]
        if not froms:
            continue
        last_from = froms[-1]
        users = [(n, arg) for n, kw, arg in instructions if kw == "USER" and n > last_from]
        if not users:
            yield _hit(
                sf,
                last_from,
                "The final stage has no USER instruction, so the container runs as root.",
                "FROM …",
            )
        elif users[-1][1].split(":")[0].strip() in ("root", "0"):
            yield _hit(
                sf,
                users[-1][0],
                "The container switches back to root as its last USER.",
                f"USER {users[-1][1]}",
            )


def docker_latest_tag(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        stages: set[str] = set()
        for number, kw, arg in _instructions(sf):
            if kw != "FROM":
                continue
            parts = [p for p in arg.split() if not p.startswith("--")]
            image = parts[0] if parts else ""
            if len(parts) >= 3 and parts[1].upper() == "AS":
                stages.add(parts[2])
            if not image or image == "scratch" or image in stages or "$" in image:
                continue
            if image.endswith(":latest") or (
                ":" not in image.rsplit("/", 1)[-1] and "@sha256:" not in image
            ):
                yield _hit(
                    sf,
                    number,
                    f"Image {image!r} is not pinned to a version; builds are not reproducible and a compromised tag is pulled silently.",
                    f"FROM {arg}",
                )


def docker_secret_env(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        for number, kw, arg in _instructions(sf):
            if kw not in ("ENV", "ARG"):
                continue
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", arg):
                name, value = m.group(1), m.group(2).strip("\"'")
                if (
                    SECRET_NAME.search(name)
                    and value
                    and not value.startswith("$")
                    and looks_like_secret_value(value)
                ):
                    yield _hit(
                        sf,
                        number,
                        f"{kw} {name} bakes a credential into the image layers (visible with `docker history`).",
                        f"{kw} {name}=…",
                    )


def docker_pipe_to_shell(ctx: ScannerContext) -> Iterator[ScannerHit]:
    pattern = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
    for sf in ctx.files:
        for number, kw, arg in _instructions(sf):
            if kw == "RUN" and pattern.search(arg):
                yield _hit(
                    sf,
                    number,
                    "A script is downloaded and piped straight into a shell; whoever controls the URL controls the build.",
                    f"RUN {arg}",
                )


# --- docker-compose ---------------------------------------------------------------------------------


def _is_compose(sf: SourceFile) -> bool:
    name = _basename(sf.path)
    return sf.language == "yaml" and (
        name.startswith(("docker-compose", "compose")) and name.endswith((".yml", ".yaml"))
    )


def _lines(sf: SourceFile) -> Iterator[tuple[int, str]]:
    for number, line in enumerate(sf.text.split("\n"), start=1):
        if not line.lstrip().startswith("#"):
            yield number, line


def compose_privileged(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in filter(_is_compose, ctx.files):
        for number, line in _lines(sf):
            if re.match(r"^\s*privileged:\s*(true|yes|on)\b", line, re.I):
                yield _hit(
                    sf,
                    number,
                    "privileged: true gives the container nearly all host capabilities; a container escape becomes root on the host.",
                    line,
                )
            elif re.match(r"^\s*network_mode:\s*['\"]?host\b", line):
                yield _hit(
                    sf,
                    number,
                    "network_mode: host removes network isolation between the container and the host.",
                    line,
                    Confidence.LOW,
                )


def compose_docker_socket(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in filter(_is_compose, ctx.files):
        for number, line in _lines(sf):
            if "/var/run/docker.sock" in line and re.match(r"^\s*-|^\s*source:", line):
                yield _hit(
                    sf,
                    number,
                    "Mounting the Docker socket gives the container control of the host's Docker daemon (equivalent to root).",
                    line,
                )


def compose_secret_env(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in filter(_is_compose, ctx.files):
        for number, line in _lines(sf):
            m = re.match(r"^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['\"]?([^'\"#\s]+)", line)
            if (
                m
                and SECRET_NAME.search(m.group(1))
                and not m.group(2).startswith("$")
                and looks_like_secret_value(m.group(2))
            ):
                yield _hit(
                    sf,
                    number,
                    f"{m.group(1)} is set to a literal credential in the compose file; use an env_file kept out of version control or Docker secrets.",
                    f"{m.group(1)}: …",
                )


# --- nginx -------------------------------------------------------------------------------------------


def nginx_autoindex(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if sf.language != "nginx":
            continue
        for number, line in _lines(sf):
            if re.match(r"^\s*autoindex\s+on\s*;", line):
                yield _hit(
                    sf,
                    number,
                    "autoindex on lists directory contents to anyone who can reach the path.",
                    line,
                )


def nginx_cors_wildcard(ctx: ScannerContext) -> Iterator[ScannerHit]:
    for sf in ctx.files:
        if sf.language != "nginx":
            continue
        credentials = bool(
            re.search(r"Access-Control-Allow-Credentials\s+['\"]?true", sf.text, re.I)
        )
        for number, line in _lines(sf):
            if re.match(
                r"^\s*add_header\s+['\"]?Access-Control-Allow-Origin['\"]?\s+['\"]?\*", line, re.I
            ):
                yield _hit(
                    sf,
                    number,
                    "Access-Control-Allow-Origin: * lets any website read responses from this server"
                    + (
                        " — combined with Allow-Credentials this is a credential-leak setup."
                        if credentials
                        else "."
                    ),
                    line,
                    Confidence.HIGH if credentials else Confidence.MEDIUM,
                )


# --- env debug flags (Laravel's APP_DEBUG has its own rule) -----------------------------------------------


def env_debug_flags(ctx: ScannerContext) -> Iterator[ScannerHit]:
    pattern = re.compile(
        r"^\s*(?:export\s+)?((?:[A-Z]+_)?DEBUG|FLASK_DEBUG|FLASK_ENV)\s*=\s*['\"]?(true|1|on|development)['\"]?\s*(#.*)?$",
        re.I,
    )
    for sf in ctx.files:
        name = _basename(sf.path)
        if sf.language != "env" or not name.startswith(".env"):
            continue
        dev_file = bool(
            re.search(r"\.(example|sample|dist|local|dev|development|test|testing|ci)$", name)
        )
        for number, line in enumerate(sf.text.split("\n"), start=1):
            m = pattern.match(line)
            if m and m.group(1).upper() != "APP_DEBUG":
                yield _hit(
                    sf,
                    number,
                    f"{m.group(1)} is enabled in an env file: debug modes expose stack traces, settings and sometimes an interactive console.",
                    f"{m.group(1)}={m.group(2)}",
                    Confidence.LOW if dev_file else Confidence.MEDIUM,
                )
