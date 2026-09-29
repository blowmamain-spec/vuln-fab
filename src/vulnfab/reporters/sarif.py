"""SARIF 2.1.0 output (docs/schema/sarif-schema-2.1.0.json is the official schema)."""

from __future__ import annotations

import json
from typing import Any

from vulnfab import __version__
from vulnfab.core.models import Confidence, Finding, Severity, TraceStep
from vulnfab.core.report import ScanResult, sort_key

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/blowmamain-spec/vuln-fab"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning reads properties["security-severity"] (CVSS-like, 0-10).
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
PRECISION = {Confidence.HIGH: "high", Confidence.MEDIUM: "medium", Confidence.LOW: "low"}


def _location(
    file: str, line: int, end_line: int | None = None, text: str | None = None
) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(line, 1)}
    if end_line and end_line >= line:
        region["endLine"] = end_line
    if text:
        region["snippet"] = {"text": text}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file, "uriBaseId": "%SRCROOT%"},
            "region": region,
        }
    }


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security", *finding.cwe]
    if finding.owasp:
        tags.append(f"OWASP-{finding.owasp}")
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": "".join(part.capitalize() for part in finding.rule_id.split("-")),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.message or finding.title},
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "precision": PRECISION[finding.confidence],
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }
    if finding.fix:
        rule["help"] = {"text": finding.fix, "markdown": f"**Fix:** {finding.fix}"}
    return rule


def _code_flow(trace: tuple[TraceStep, ...]) -> dict[str, Any]:
    locations = []
    for step in trace:
        location = _location(step.file, step.line)
        location["message"] = {"text": f"{step.kind}: {step.detail}" if step.detail else step.kind}
        locations.append({"location": location})
    return {"threadFlows": [{"locations": locations}]}


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    message = finding.message or finding.title
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            _location(finding.file, finding.line, finding.end_line, finding.snippet or None)
        ],
        "partialFingerprints": {"vulnfab/v1": finding.fingerprint},
        "properties": {
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "cwe": list(finding.cwe),
        },
    }
    if finding.tier:
        result["properties"]["tier"] = finding.tier
    if finding.unresolved_hops:
        result["properties"]["unresolvedHops"] = finding.unresolved_hops
    if len(finding.trace) >= 2:
        result["codeFlows"] = [_code_flow(finding.trace)]
    return result


def to_sarif_dict(result: ScanResult) -> dict[str, Any]:
    findings = sorted(result.findings, key=sort_key)
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(finding.rule_id, _rule(finding))
    ids = list(rules)
    notifications = [
        {
            "level": "note",
            "message": {"text": f"{u.kind}: {u.detail}" if u.detail else u.kind},
            "locations": [_location(u.file, u.line)],
        }
        for u in result.coverage.unresolved
    ]
    invocation: dict[str, Any] = {"executionSuccessful": True}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnfab",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "invocations": [invocation],
                "results": [_result(f, ids.index(f.rule_id)) for f in findings],
                "properties": {
                    "stacks": result.stacks,
                    "filesScanned": result.coverage.files_scanned,
                },
            }
        ],
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_sarif_dict(result), indent=2, ensure_ascii=False) + "\n"
