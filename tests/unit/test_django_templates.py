"""Django template scanners (WP-6.3)."""

from __future__ import annotations

from vulnfab.core.models import Confidence, SourceFile
from vulnfab.core.scannerrules import ScannerContext
from vulnfab.plugins.django import templates


def hits(fn, text: str, path: str = "app/templates/x.html"):
    sf = SourceFile(path, "html", text, "0" * 64)
    return list(fn(ScannerContext([sf], None)))  # type: ignore[arg-type]


def test_split_filters_respects_quotes() -> None:
    assert templates.split_filters('a.b|default:"x|y"|safe') == ("a.b", ["default", "safe"])
    assert templates.split_filters("plain") == ("plain", [])


def test_blank_comments_keeps_line_numbers() -> None:
    text = "a\n{# one\ntwo #}\n{% comment %}\nx|safe\n{% endcomment %}\nb\n"
    blanked = templates.blank_comments(text)
    assert blanked.count("\n") == text.count("\n")
    assert "safe" not in blanked


def test_safe_reports_line_and_trusted_base_is_low() -> None:
    found = hits(templates.safe_filter, "<p>x</p>\n{{ form.as_p|safe }}\n{{ note|safe }}\n")
    assert [(h.line, h.confidence) for h in found] == [(2, Confidence.LOW), (3, Confidence.MEDIUM)]


def test_safe_after_escaping_filter_is_ignored() -> None:
    assert not hits(templates.safe_filter, "{{ x|escape|safe }}{{ y|striptags|safe }}")


def test_form_include_downgrades_to_low() -> None:
    text = '<form method="POST">{% include "fields.html" %}</form>'
    (h,) = hits(templates.form_without_csrf, text)
    assert h.confidence is Confidence.LOW


def test_non_template_html_outside_templates_dir_is_skipped() -> None:
    assert not hits(templates.form_without_csrf, '<form method="post"></form>', "static/page.html")
