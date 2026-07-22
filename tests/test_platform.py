"""End-to-end wiring tests for run_campaign — the cost governor, tracer binding, and
the exploits-new delta. These assert the WIRING inside the loop (which had no test),
not the pure predicates. Fully offline: respx-mocked target, keyless settings, a
monkeypatched Orchestrator.run_seed to control each seed's effect deterministically."""
from __future__ import annotations

import respx
from httpx import Response

from adversaryforge import platform as plat
from adversaryforge.agents.orchestrator import Orchestrator
from adversaryforge.config import Settings
from adversaryforge.contracts import (
    AttackCategory,
    ConfirmedExploit,
    Outcome,
    Severity,
    TranscriptTurn,
    Verdict,
)
from adversaryforge.observability.store import Store
from adversaryforge.observability.tracing import trace

BASE = "http://test.local"


def _settings(tmp_path, monkeypatch, budget="0"):
    monkeypatch.setenv("ADVERSARYFORGE_TARGET_BASE_URL", BASE)
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("ADVERSARYFORGE_MIN_REQUEST_GAP_S", "0.0")
    monkeypatch.setenv("ADVERSARYFORGE_NOSIGNAL_HALT_USD", budget)
    monkeypatch.setenv("ADVERSARYFORGE_TRACE", "1")
    return Settings()


def _fail_verdict():
    return Verdict(verdict_id="vd", attempt_id="at", outcome=Outcome.failure,
                   severity=Severity.info, confidence=0.9, method="deterministic",
                   rationale="stub")


def _exploit(eid: str, marker: str):
    return ConfirmedExploit(
        exploit_id=eid, attempt_id="at", verdict_id="vd",
        category=AttackCategory.data_exfiltration, severity=Severity.high,
        target_invariant="INV-AUTHZ-PATIENT",
        minimal_transcript=[TranscriptTurn(role="attacker", content=marker)],
        expected_safe="403", observed="y")


async def test_run_campaign_cost_governor_halts_on_no_signal(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch, budget="0.5")
    calls = {"n": 0}

    async def fake_run_seed(self, seed, directive, executor, judge, run_id,
                            mutator=None, n_variants=8):
        calls["n"] += 1
        self._store.log_cost(run_id, "redteam", "test", 0, 0, 1.0)  # over budget
        return (None, _fail_verdict())  # no confirmed exploit -> no signal

    monkeypatch.setattr(Orchestrator, "run_seed", fake_run_seed)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        result = await plat.run_campaign(settings=st)

    assert result.halted_no_signal is True
    assert calls["n"] == 1  # broke out of the loop after the first (no-signal) seed
    actions = {e["action"] for e in Store(st.db_path).agent_timeline(result.run_id)}
    assert "cost_halt" in actions


async def test_run_campaign_binds_tracer_during_the_loop(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch, budget="0")  # governor disabled

    async def fake_run_seed(self, seed, directive, executor, judge, run_id,
                            mutator=None, n_variants=8):
        with trace("wiring.probe", "judge", seed=seed.id) as sp:  # only records if a tracer is bound
            sp.set("ok", True)
        return (None, _fail_verdict())

    monkeypatch.setattr(Orchestrator, "run_seed", fake_run_seed)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        result = await plat.run_campaign(settings=st, limit=1)

    spans = Store(st.db_path).get_spans(result.run_id)
    assert any(s["name"] == "wiring.probe" for s in spans)  # tracer WAS bound in the loop


async def test_run_campaign_exploits_new_is_a_delta(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch, budget="0")
    pre = Store(st.db_path)
    pre.record_exploit(_exploit("ex_pre", "pre-existing"))  # already in the DB
    pre.close()

    inserted = {"done": False}

    async def fake_run_seed(self, seed, directive, executor, judge, run_id,
                            mutator=None, n_variants=8):
        if not inserted["done"]:
            self._store.record_exploit(_exploit("ex_new", "new-this-run"))
            inserted["done"] = True
        return (None, _fail_verdict())

    monkeypatch.setattr(Orchestrator, "run_seed", fake_run_seed)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        result = await plat.run_campaign(settings=st, limit=1)

    assert result.exploits_new == 1  # only the one added this run, not the pre-existing


async def test_run_campaign_real_chain_promotes_an_exploit(tmp_path, monkeypatch):
    # No monkeypatch of run_seed: exercise the REAL Orchestrator -> executor -> Judge
    # -> _promote chain end-to-end against a respx-mocked target.
    monkeypatch.setenv("ADVERSARYFORGE_TARGET_BASE_URL", BASE)
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADVERSARYFORGE_MIN_REQUEST_GAP_S", "0.0")
    monkeypatch.setenv("ADVERSARYFORGE_NOSIGNAL_HALT_USD", "0")
    st = Settings()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        # /ready leaks dependency inventory -> INV-INFO-DISCLOSURE success.
        router.get(f"{BASE}/ready").mock(return_value=Response(
            200, json={"dependencies": {"openemr": "ok"}, "database": "ok"}))
        router.route().mock(return_value=Response(401, json={}))  # everything else: defense held
        result = await plat.run_campaign(settings=st, categories=["data_exfiltration"])

    assert result.successes >= 1        # di-ready-enum promoted via the real chain
    assert result.exploits_new >= 1
    assert Store(st.db_path)._conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0] >= 1


def test_meter_judge_llm_logs_delta_not_cumulative(tmp_path):
    # The Judge adjudicator cost is cumulative; the meter must log per-call DELTAS
    # into the ledger (double-counting would corrupt the cost governor + analysis).
    from adversaryforge.agents.orchestrator import Orchestrator
    from adversaryforge.redteam.seeds import SeedLibrary

    store = Store(tmp_path / "t.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    orch = Orchestrator(store, SeedLibrary(seeds=[]))

    usage = {"v": (10, 5, 0.01)}

    def _adj(view):  # a callable carrying a cumulative .usage(), like make_llm_adjudicator
        return None
    _adj.usage = lambda: usage["v"]

    class _Judge:
        _llm = _adj

    j = _Judge()
    orch._meter_judge_llm(j, rid)          # first: cumulative 0.01 -> log 0.01
    usage["v"] = (25, 12, 0.03)
    orch._meter_judge_llm(j, rid)          # second: cumulative 0.03 -> log delta 0.02
    orch._meter_judge_llm(j, rid)          # third: no change -> log nothing

    rows = store._conn.execute(
        "SELECT usd, input_tokens, output_tokens FROM cost_ledger ORDER BY id").fetchall()
    assert [round(r[0], 4) for r in rows] == [0.01, 0.02]      # deltas, not [0.01, 0.03]
    assert [r[1] for r in rows] == [10, 15] and [r[2] for r in rows] == [5, 7]
    store.close()
