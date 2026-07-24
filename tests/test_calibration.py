"""Judge drift gate — per-run Cohen's-kappa calibration against the frozen gold set.
This is the plan's headline anti-drift control; here we prove (a) the kappa math, (b)
the current Judge scores a perfect gold-set kappa, and (c) a DRIFTED Judge fails the
gate and, through run_campaign, halts the campaign fail-closed BEFORE it attacks."""
from __future__ import annotations

import respx
from httpx import Response

from adversaryforge import platform as plat
from adversaryforge.agents.calibration import _gold, calibrate_judge, cohens_kappa
from adversaryforge.agents.judge import Judge
from adversaryforge.config import Settings
from adversaryforge.contracts import Outcome, Severity

BASE = "http://test.local"


def test_cohens_kappa_math():
    assert cohens_kappa(["a", "b", "a"], ["a", "b", "a"]) == 1.0     # perfect
    assert cohens_kappa([], []) == 1.0                               # empty
    assert round(cohens_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]), 3) == 0.0  # chance


def test_current_judge_scores_a_perfect_gold_set_kappa():
    c = calibrate_judge(Judge())
    assert c.kappa == 1.0
    assert c.passed is True
    assert c.agreements == c.n == len(_gold())
    assert c.disagreements == []


def _drift_authz(self, view, status, action, answer, claims, ev):
    # A drifting / over-eager Judge: call every authz case a critical success.
    return self._verdict(view, Outcome.success, 0.9, Severity.critical, "drift", evidence=ev)


def test_drifted_judge_fails_the_gate(monkeypatch):
    monkeypatch.setattr(Judge, "_judge_authz", _drift_authz)
    c = calibrate_judge(Judge(), threshold=0.8)
    assert c.passed is False
    # The gate fails closed via the documented "two+ flips fail" rule. (A bare kappa<0.8
    # check was a gold-set-size artifact: once the gold set covers all 11 rule-backed
    # invariants, a single-rule drift flips ~2 of 22 cases and no longer drags the
    # all-cases kappa below 0.8 — so we assert the real trigger, the disagreement count.)
    assert len(c.disagreements) >= 2
    assert any(d["invariant"] == "INV-AUTHZ-PATIENT" for d in c.disagreements)


async def test_run_campaign_fails_closed_on_judge_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("ADVERSARYFORGE_TARGET_BASE_URL", BASE)
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("ADVERSARYFORGE_MIN_REQUEST_GAP_S", "0.0")
    monkeypatch.setattr(Judge, "_judge_authz", _drift_authz)
    st = Settings()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.route().mock(return_value=Response(401, json={}))
        result = await plat.run_campaign(settings=st)

    assert result.calibration_passed is False       # drift gate tripped (fail-closed)
    assert result.total == 0                         # NO seeds attacked — halted first
    # kappa is recorded and reflects the drift; fail-closed is asserted above via
    # calibration_passed (the 2+-disagreement rule, robust to gold-set size).
    assert result.calibration_kappa is not None and result.calibration_kappa < 1.0


async def test_run_campaign_records_kappa_when_judge_is_healthy(tmp_path, monkeypatch):
    monkeypatch.setenv("ADVERSARYFORGE_TARGET_BASE_URL", BASE)
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("ADVERSARYFORGE_MIN_REQUEST_GAP_S", "0.0")
    st = Settings()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.route().mock(return_value=Response(401, json={}))
        result = await plat.run_campaign(settings=st, limit=1)

    assert result.calibration_passed is True
    assert result.calibration_kappa == 1.0           # healthy Judge → perfect gold-set agreement
