"""Cost governor — the case study requires the platform to halt/redirect when cost
accumulates without producing signal. This tests the halt decision directly."""
from __future__ import annotations

from adversaryforge.observability.store import Store
from adversaryforge.platform import should_halt_no_signal


def test_halts_when_budget_spent_with_zero_signal():
    assert should_halt_no_signal(spent_usd=2.5, budget_usd=2.0, confirmed=0) is True
    assert should_halt_no_signal(spent_usd=2.0, budget_usd=2.0, confirmed=0) is True


def test_does_not_halt_when_there_is_signal():
    # Spending is fine as long as it's producing confirmed exploits.
    assert should_halt_no_signal(spent_usd=10.0, budget_usd=2.0, confirmed=1) is False


def test_does_not_halt_under_budget():
    assert should_halt_no_signal(spent_usd=0.5, budget_usd=2.0, confirmed=0) is False


def test_disabled_when_budget_non_positive():
    assert should_halt_no_signal(spent_usd=100.0, budget_usd=0.0, confirmed=0) is False
    assert should_halt_no_signal(spent_usd=100.0, budget_usd=-1.0, confirmed=0) is False


def test_cost_by_agent_groups_spend_per_agent(tmp_path):
    # The docs claim spend is broken down per agent (Red Team vs Judge). cost_by_agent
    # must actually GROUP BY agent — not merge them like cost_summary's flat total.
    store = Store(tmp_path / "c.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    store.log_cost(rid, "redteam", "hermes", 100, 20, 0.10)
    store.log_cost(rid, "redteam", "hermes", 100, 20, 0.10)  # two redteam calls
    store.log_cost(rid, "judge", "claude", 200, 50, 0.05)
    rows = store.cost_by_agent(rid)
    by = {r["agent"]: r for r in rows}
    assert set(by) == {"redteam", "judge"}                 # split, not merged
    assert by["redteam"]["usd"] == 0.20 and by["redteam"]["llm_calls"] == 2
    assert by["judge"]["usd"] == 0.05 and by["judge"]["input_tokens"] == 200
    assert [r["agent"] for r in rows] == ["redteam", "judge"]  # ORDER BY usd DESC
    # And the flat summary still totals everything (the two views agree on the sum).
    assert store.cost_summary(rid)["usd"] == 0.25
    store.close()
