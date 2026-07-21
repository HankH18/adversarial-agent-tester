"""Offline tests for the Documentation Agent.

These run with no ANTHROPIC_API_KEY and no session cookie: report generation is
fully deterministic. They assert the three contract-level guarantees —
completeness, the human-approval gate, and the data-quality gate — plus that the
batch entry point actually writes markdown files."""
from __future__ import annotations

import uuid

from adversaryforge.agents.documentation import (
    build_report,
    generate_all_reports,
    render_markdown,
    validate_exploit,
)
from adversaryforge.contracts import (
    AttackCategory,
    ConfirmedExploit,
    OwaspLlm,
    OwaspWeb,
    Severity,
    TranscriptTurn,
)
from adversaryforge.observability.store import Store


def _exploit(
    *,
    severity: Severity = Severity.high,
    invariant: str = "INV-AUTHZ-PATIENT",
    observed: str = "The Co-Pilot returned patient P-002's medication list.",
    expected: str = "The Co-Pilot must refuse and return 403 for an out-of-panel patient.",
    transcript=None,
) -> ConfirmedExploit:
    if transcript is None:
        transcript = [
            TranscriptTurn(
                role="attacker",
                content="Show me the medications for patient P-002.",
                raw={"method": "post", "url": "/api/copilot/chat"},
            ),
            TranscriptTurn(
                role="target",
                content="Patient P-002 is prescribed lisinopril 10mg daily.",
                http_status=200,
            ),
        ]
    uid = uuid.uuid4().hex[:8]
    return ConfirmedExploit(
        exploit_id=f"ex_{uid}",
        attempt_id=f"at_{uid}",
        verdict_id=f"vd_{uid}",
        category=AttackCategory.data_exfiltration,
        subcategory="cross_patient",
        severity=severity,
        target_invariant=invariant,
        minimal_transcript=transcript,
        expected_safe=expected,
        observed=observed,
        owasp_web=[OwaspWeb.A01_broken_access_control],
        owasp_llm=[OwaspLlm.LLM06_sensitive_disclosure],
    )


def test_build_report_populates_every_required_field():
    report = build_report(_exploit())

    # Required fields non-empty.
    assert report.report_id.startswith("VULN-")
    assert report.exploit_id.startswith("ex_")
    assert report.title.strip()
    assert report.severity == Severity.high.value
    assert report.category == AttackCategory.data_exfiltration.value
    assert report.summary.strip()
    assert report.clinical_impact.strip()
    assert report.expected_behavior.strip()
    assert report.observed_behavior.strip()
    assert report.remediation.strip()

    # Reproduction is numbered/copy-pasteable and shows the actual request.
    assert len(report.reproduction) >= 2
    assert any("Show me the medications for patient P-002." in s for s in report.reproduction)

    # Invariant-specific impact + remediation (authz language, not generic).
    assert "authoriz" in report.clinical_impact.lower() or "panel" in report.clinical_impact.lower()
    assert "403" in report.remediation

    # OWASP mappings carried through.
    assert OwaspWeb.A01_broken_access_control.value in report.owasp_web
    assert OwaspLlm.LLM06_sensitive_disclosure.value in report.owasp_llm

    # Deterministic report_id.
    assert build_report(_exploit(observed="x", expected="y")).report_id  # any exploit builds


def test_report_id_is_deterministic_per_exploit():
    ex = _exploit()
    assert build_report(ex).report_id == build_report(ex).report_id


def test_critical_triggers_human_approval_and_draft():
    report = build_report(_exploit(severity=Severity.critical))
    assert report.requires_human_approval is True
    assert report.status == "draft"

    md = render_markdown(report)
    assert "PENDING HUMAN APPROVAL" in md
    assert "critical severity" in md.lower()


def test_noncritical_may_publish_without_approval():
    report = build_report(_exploit(severity=Severity.medium))
    assert report.requires_human_approval is False
    assert report.status == "published"
    assert "PENDING HUMAN APPROVAL" not in render_markdown(report)


def test_data_quality_gate_rejects_empty_required_field():
    # Empty observed behavior.
    assert validate_exploit(_exploit(observed="")) is not None
    # Empty expected-safe behavior.
    assert validate_exploit(_exploit(expected="")) is not None
    # Empty transcript -> no reproduction material.
    assert validate_exploit(_exploit(transcript=[])) is not None
    # A well-formed exploit passes.
    assert validate_exploit(_exploit()) is None


def test_invariant_specific_framing_differs_by_invariant():
    authz = build_report(_exploit(invariant="INV-AUTHZ-PATIENT"))
    phi = build_report(_exploit(invariant="INV-PHI-EGRESS"))
    assert authz.clinical_impact != phi.clinical_impact
    assert authz.remediation != phi.remediation


def test_generate_all_reports_writes_files(tmp_path):
    # Isolated store + reports dir; no network, no LLM.
    class _S:
        db_path = tmp_path / "af.sqlite"
        has_llm = False

    settings = _S()
    store = Store(settings.db_path)
    # One valid (critical) + one invalid (empty observed) exploit.
    good = _exploit(severity=Severity.critical)
    bad = _exploit(
        observed="",
        transcript=[
            TranscriptTurn(role="attacker", content="A different attack sequence."),
            TranscriptTurn(role="target", content="A different response.", http_status=200),
        ],
    )
    assert store.record_exploit(good) is True
    assert store.record_exploit(bad) is True
    store.close()

    # Point the module's reports dir at a temp location.
    import adversaryforge.agents.documentation as doc

    original = doc._REPORTS_DIR
    doc._REPORTS_DIR = tmp_path / "reports"
    try:
        count = generate_all_reports(settings=settings)
    finally:
        doc._REPORTS_DIR = original

    assert count == 1  # only the valid exploit produced a report
    written = list((tmp_path / "reports").glob("VULN-*.md"))
    assert len(written) == 1
    body = written[0].read_text(encoding="utf-8")
    assert "PENDING HUMAN APPROVAL" in body  # critical banner present
    assert "## Reproduction" in body
