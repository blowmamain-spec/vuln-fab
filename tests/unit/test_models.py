import json

from vulnfab.core.models import (
    Confidence,
    Finding,
    SchemaModel,
    Severity,
    Table,
    TraceStep,
    to_jsonable,
)


def _finding() -> Finding:
    return Finding(
        rule_id="x-test",
        title="t",
        cwe=("CWE-89",),
        owasp=None,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        tier="B",
        file="a.py",
        line=3,
        end_line=4,
        snippet="eval(x)",
        trace=(TraceStep("a.py", 3, "sink", "eval"),),
    )


def test_finding_serialises_to_json() -> None:
    data = to_jsonable(_finding())
    text = json.dumps(data)
    loaded = json.loads(text)
    assert loaded["severity"] == "high"
    assert loaded["cwe"] == ["CWE-89"]
    assert loaded["trace"][0]["kind"] == "sink"


def test_priority_and_confidence_lowering() -> None:
    f = _finding()
    assert f.priority == 4 * 0.7
    assert Confidence.HIGH.lowered() is Confidence.MEDIUM
    assert Confidence.LOW.lowered(3) is Confidence.LOW


def test_schema_model_serialises_sets() -> None:
    model = SchemaModel(tables={"public.t": Table(name="t", rls_enabled=True)})
    data = to_jsonable(model)
    assert data["tables"]["public.t"]["rls_enabled"] is True
    assert data["tables"]["public.t"]["qualified_name" if False else "schema"] == "public"
