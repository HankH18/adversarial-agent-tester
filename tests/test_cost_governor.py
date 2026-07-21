"""Cost governor — the case study requires the platform to halt/redirect when cost
accumulates without producing signal. This tests the halt decision directly."""
from __future__ import annotations

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
