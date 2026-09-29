"""Dockerfile / compose / nginx scanners: edge cases beyond the rule fixtures (WP-8.1)."""
# ruff: noqa: E501

from __future__ import annotations

from vulnfab.core.loader import detect_language
from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.scannerrules import ScannerContext
from vulnfab.scanners import infra


def run(fn, text: str, path: str = "Dockerfile", language: str = "dockerfile"):  # type: ignore[no-untyped-def]
    sf = SourceFile(path, language, text, "0" * 64)
    return list(fn(ScannerContext([sf], None)))  # type: ignore[arg-type]


def test_language_detection() -> None:
    assert detect_language("Dockerfile") == "dockerfile"
    assert detect_language("svc/app.dockerfile") == "dockerfile"
    assert detect_language("deploy/nginx/site.conf") == "nginx"
    assert detect_language("etc/other.conf") is None


def test_root_check_uses_only_the_final_stage() -> None:
    text = "FROM golang:1.22 AS build\nUSER build\nFROM alpine:3.19\nCOPY --from=build /x /x\n"
    (hit,) = run(infra.docker_runs_as_root, text)
    assert hit.line == 3  # the final stage never drops root, whatever the build stage did


def test_user_root_last_is_flagged_and_numeric_uid_is_fine() -> None:
    assert run(infra.docker_runs_as_root, "FROM a:1\nUSER root\n")
    assert not run(infra.docker_runs_as_root, "FROM a:1\nUSER 1000:1000\n")


def test_continuation_lines_are_joined() -> None:
    text = "FROM alpine:3.19\nRUN apk add curl \\\n && curl -fsSL https://x.sh \\\n | sh\n"
    (hit,) = run(infra.docker_pipe_to_shell, text)
    assert hit.line == 2


def test_latest_ignores_stage_references_and_variables() -> None:
    text = "FROM base:1.0 AS base\nFROM base\nARG IMG=x:1\nFROM $IMG\n"
    assert not run(infra.docker_latest_tag, text)


def test_compose_ignores_comments_and_other_yaml() -> None:
    text = "# privileged: true\nservices:\n  a:\n    image: x:1\n"
    assert not run(infra.compose_privileged, text, "docker-compose.yml", "yaml")
    assert not run(infra.compose_privileged, "privileged: true\n", "config.yml", "yaml")


def test_nginx_cors_with_credentials_is_high() -> None:
    text = "add_header Access-Control-Allow-Origin * always;\nadd_header Access-Control-Allow-Credentials true;\n"
    (hit,) = run(infra.nginx_cors_wildcard, text, "nginx.conf", "nginx")
    assert hit.confidence is Confidence.HIGH


def test_env_debug_skips_app_debug_and_lowers_example_files() -> None:
    text = "APP_DEBUG=true\nDJANGO_DEBUG=1\n"
    (hit,) = run(infra.env_debug_flags, text, ".env", "env")
    assert hit.line == 2 and hit.confidence is Confidence.MEDIUM
    (example,) = run(infra.env_debug_flags, text, ".env.example", "env")
    assert example.confidence is Confidence.LOW
