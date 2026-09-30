"""The HTML report must never turn scanned content into active markup (WP-10.2)."""

from __future__ import annotations

from html.parser import HTMLParser

from vulnfab.core.models import Confidence, Finding, Severity, TraceStep, Unresolved
from vulnfab.core.report import Coverage, ScanResult
from vulnfab.reporters import html_reporter

HOSTILE = "<script>alert(1)</script>"
ATTR = '"><img src=x onerror=alert(2)>'


class Audit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.event_attrs: list[str] = []
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        self.tags.append(tag)
        for name, value in attrs:
            if name.startswith("on"):
                self.event_attrs.append(name)
            if name in ("href", "src") and value:
                self.urls.append(value)


def hostile_result() -> ScanResult:
    finding = Finding(
        rule_id="tpy-xss",
        title=f"t {HOSTILE}",
        cwe=(f"CWE-79{ATTR}",),
        owasp=HOSTILE,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tier="A",
        file=f"a{ATTR}.py",
        line=3,
        end_line=3,
        snippet=f"print('{HOSTILE}')",
        trace=(TraceStep(f"b{ATTR}.py", 1, "source", HOSTILE), TraceStep("c.py", 2, "sink", "x")),
        fix=HOSTILE,
        fingerprint=f"fp{ATTR}",
        message=f"m {HOSTILE}",
    )
    cov = Coverage(
        files_scanned=1,
        unresolved=[Unresolved("dynamic", f"u{ATTR}.py", 1, HOSTILE)],
        assumptions=[HOSTILE],
    )
    return ScanResult(f"repo {HOSTILE}", [f"stack{ATTR}"], [finding], cov)


def test_hostile_content_is_inert() -> None:
    page = html_reporter.render(hostile_result())
    audit = Audit()
    audit.feed(page)
    assert "script" not in audit.tags
    assert "img" not in audit.tags
    assert audit.event_attrs == []
    assert audit.urls == []
    assert HOSTILE not in page and "&lt;script&gt;" in page
    assert "onerror=alert(2)>" not in page.replace("&gt;", "")  # only inside escaped text


def test_page_is_self_contained_and_scriptless() -> None:
    page = html_reporter.render(hostile_result())
    assert "<script" not in page.lower()
    assert "http://" not in page and "https://" not in page
    assert page.startswith("<!doctype html>")


def test_empty_report_and_grouping() -> None:
    empty = ScanResult("r", ["generic"], [], Coverage())
    assert "No findings" in html_reporter.render(empty)
    many = hostile_result()
    many.findings.append(
        Finding(
            "x-y",
            "Low one",
            (),
            None,
            Severity.LOW,
            Confidence.LOW,
            None,
            "z.py",
            1,
            1,
            "s",
            message="m",
        )
    )
    page = html_reporter.render(many)
    assert page.index("High") < page.index("Low")


def test_triage_page_has_one_static_script_and_no_scan_data_in_it() -> None:
    page = html_reporter.render_triage(hostile_result())
    assert page.lower().count("<script") == 1  # hostile text is escaped, not a tag
    start = page.index("<script>") + len("<script>")
    script = page[start : page.index("</script>", start)]
    assert script == html_reporter.SCRIPT
    assert "Content-Security-Policy" in page and "connect-src" not in page
    assert "default-src 'none'" in page
    audit = Audit()
    audit.feed(page)
    assert audit.event_attrs == [] and audit.urls == []
    assert HOSTILE not in page.replace(html_reporter.SCRIPT, "")


def test_triage_page_marks_findings_for_the_script() -> None:
    page = html_reporter.render_triage(hostile_result())
    assert "data-fp=" in page and "data-rule='tpy-xss'" in page
    assert "Export verdicts" in page
    assert "data-fp=" not in html_reporter.render(hostile_result())
