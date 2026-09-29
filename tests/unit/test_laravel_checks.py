"""Laravel Blade scanners, config scanners and model-aware IDOR refinement (WP-7.3/7.4)."""
# ruff: noqa: E501

from __future__ import annotations

from pathlib import Path

from vulnfab.core.loader import Repo
from vulnfab.core.models import Confidence, Finding, Severity, SourceFile
from vulnfab.core.scannerrules import ScannerContext
from vulnfab.plugins.laravel import LaravelPlugin, blade, config


def scan(fn, text: str, path: str = "resources/views/x.blade.php", language: str = "blade"):
    sf = SourceFile(path, language, text, "0" * 64)
    return list(fn(ScannerContext([sf], None)))  # type: ignore[arg-type]


def test_blade_comment_and_verbatim_are_ignored() -> None:
    text = "{{-- {!! $a !!} --}}\n@verbatim\n{!! $b !!}\n@endverbatim\n{!! $c !!}\n"
    hits = scan(blade.unescaped_output, text)
    assert [h.line for h in hits] == [5]


def test_blade_trusted_helpers_are_low_or_skipped() -> None:
    text = "{!! csrf_field() !!}\n{!! e($x) !!}\n{!! $posts->links() !!}\n{!! $x !!}\n"
    hits = scan(blade.unescaped_output, text)
    assert [(h.line, h.confidence) for h in hits] == [
        (1, Confidence.LOW),
        (3, Confidence.LOW),
        (4, Confidence.MEDIUM),
    ]


def test_blade_csrf_variants() -> None:
    ok = '<form method="POST">{!! csrf_field() !!}</form><form method="post"><input name="_token"></form>'
    assert not scan(blade.form_without_csrf, ok)
    bad = '<form method="POST" action="/x">@include("fields")</form>'
    (h,) = scan(blade.form_without_csrf, bad)
    assert h.confidence is Confidence.LOW


def test_env_scanners() -> None:
    env = "APP_DEBUG=true\nAPP_KEY=base64:abc\n"
    debug = scan(config.app_debug, env, ".env", "env")
    assert debug[0].confidence is Confidence.MEDIUM
    assert scan(config.app_debug, env, ".env.production", "env")[0].confidence is Confidence.HIGH
    assert scan(config.app_debug, env, ".env.example", "env")[0].confidence is Confidence.LOW
    assert len(scan(config.app_key_committed, env, ".env", "env")) == 1
    assert not scan(config.app_key_committed, env, ".env.example", "env")
    assert not scan(config.app_key_committed, "APP_KEY=\n", ".env", "env")


def test_config_app_php_debug_literal() -> None:
    php = "<?php\nreturn [\n    'debug' => true,\n    'env' => env('APP_ENV'),\n];\n"
    hits = scan(config.app_debug, php, "config/app.php", "php")
    assert [h.line for h in hits] == [3]
    assert not scan(
        config.app_debug,
        "<?php\nreturn ['debug' => (bool) env('APP_DEBUG', false)];\n",
        "config/app.php",
        "php",
    )


def test_refine_lowers_idor_for_tables_without_owner(tmp_path: Path) -> None:
    files = {
        "artisan": "x",
        "database/migrations/2024_01_01_000000_a.php": (
            "<?php\nreturn new class {\n public function up() {\n"
            "  Schema::create('countries', function ($t) { $t->id(); $t->string('name'); });\n"
            "  Schema::create('orders', function ($t) { $t->id(); $t->foreignId('user_id')->constrained(); });\n"
            " }\n};\n"
        ),
    }
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    plugin = LaravelPlugin()
    model = plugin.extract_schema(Repo(tmp_path))
    assert model is not None

    def finding(snippet: str) -> Finding:
        return Finding(
            "tphp-idor",
            "t",
            (),
            None,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "B",
            "c.php",
            1,
            1,
            snippet,
            message="m",
        )

    raw = [
        (finding("$c = Country::find($id);"), "a"),
        (finding("$o = Order::findOrFail($id);"), "b"),
        (finding("$x = $repo->find($id);"), "c"),
    ]
    out = plugin.refine(raw, model)
    assert [f.confidence for f, _ in out] == [Confidence.LOW, Confidence.MEDIUM, Confidence.MEDIUM]
