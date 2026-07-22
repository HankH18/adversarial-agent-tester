"""Deterministic target selection — the Orchestrator's scoring policy is auditable
and testable (no LLM in the decision path). Locks the gap-bonus, open-findings lift,
saturation penalty, and next_directive output."""
from __future__ import annotations

from adversaryforge.agents.orchestrator import Orchestrator
from adversaryforge.contracts import (
    AttackAttempt,
    AttackCategory,
    ConfirmedExploit,
    Outcome,
    Severity,
    TranscriptTurn,
    Verdict,
)
from adversaryforge.observability.store import Store
from adversaryforge.redteam.seeds import SeedLibrary


def _orch(tmp_path):
    return Orchestrator(Store(tmp_path / "t.sqlite"), SeedLibrary.load())


def test_fresh_store_gives_top_score_8_and_expected_ordering(tmp_path):
    orch = _orch(tmp_path)
    scored = orch.score_categories(authenticated=True)
    # Fresh store: base priority + gap_bonus(3.0). Highest-priority categories = 8.0.
    assert scored[0][1] == 8.0
    top = {c for c, s, _ in scored if s == 8.0}
    assert top & {"data_exfiltration", "prompt_injection"}  # the base-5 categories


def test_open_exploit_lifts_its_category_score(tmp_path):
    orch = _orch(tmp_path)
    store = orch._store  # noqa: SLF001
    store.record_exploit(ConfirmedExploit(
        exploit_id="ex_open", attempt_id="at", verdict_id="vd",
        category=AttackCategory.tool_misuse, severity=Severity.high,
        target_invariant="INV-WRITE-GATED",
        minimal_transcript=[TranscriptTurn(role="attacker", content="probe")],
        expected_safe="503", observed="y"))
    scored = dict((c, s) for c, s, _ in orch.score_categories(authenticated=True))
    reason = {c: r for c, _, r in orch.score_categories(authenticated=True)}["tool_misuse"]
    assert scored["tool_misuse"] >= 3.0 + 1.0  # base(3) + open_bonus(+1)
    assert "open=1" in reason or "open+1" in reason


def test_next_directive_targets_the_top_scored_category(tmp_path):
    orch = _orch(tmp_path)
    d = orch.next_directive(authenticated=True)
    assert d is not None
    top_cat = orch.score_categories(authenticated=True)[0][0]
    assert (d.category.value if hasattr(d.category, "value") else d.category) == top_cat
    assert d.seed_ids and d.target_invariant  # populated from that category's seeds


def test_saturated_all_defended_category_is_penalized(tmp_path):
    orch = _orch(tmp_path)
    store = orch._store  # noqa: SLF001
    rid = store.start_run("http://t", "v", "test", False)
    # 8 attempts in one category, all defended (failure) -> saturation -1.0.
    for i in range(8):
        at = AttackAttempt(attempt_id=f"a{i}", directive_id="d",
                           category=AttackCategory.denial_of_service,
                           target_invariant="INV-RATE-LIMIT", expected_safe="x",
                           transcript=[TranscriptTurn(role="attacker", content="p")])
        store.record_attempt(rid, at)
        store.record_verdict(rid, Verdict(verdict_id=f"v{i}", attempt_id=f"a{i}",
                                          outcome=Outcome.failure, severity=Severity.info,
                                          confidence=0.9, method="deterministic", rationale="x"))
    reason = {c: r for c, _, r in orch.score_categories(authenticated=True)}["denial_of_service"]
    assert "sat-1" in reason  # saturation penalty applied
