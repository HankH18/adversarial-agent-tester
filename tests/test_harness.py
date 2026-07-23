"""Regression harness tests — fully offline (respx-mocked target, no live calls).

Covers the harness's load-bearing invariants:
  * a case whose re-judge yields FAILURE (defense held) -> passed
  * a case whose re-judge yields SUCCESS (vuln live) -> failed, and a previously
    'resolved' exploit is reopened + counted as a reappearance
  * an auth-required case with no session -> skipped (neither pass nor fail)
  * cross-category regression detection between two passfail snapshots
"""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from adversaryforge.config import Settings
from adversaryforge.contracts import (
    AttackCategory,
    ConfirmedExploit,
    Outcome,
    RegressionCandidate,
    Severity,
    TranscriptTurn,
)
from adversaryforge.harness.regression import (
    _decide_case,
    detect_cross_category_regression,
    run_regression,
)
from adversaryforge.observability.store import Store

BASE = "http://testserver"


# ── pure decision core ──────────────────────────────────────────────────────
def test_regression_meter_judge_llm_logs_delta_not_cumulative(tmp_path):
    # The regression path has its OWN _meter_judge_llm copy (separate from the
    # Orchestrator's), and the hermetic suite forces no API key so its delta branch
    # otherwise never runs. It must log per-call DELTAS, not cumulative totals —
    # double-counting would corrupt keyed-regression cost accounting.
    from adversaryforge.harness.regression import _meter_judge_llm

    store = Store(tmp_path / "r.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    usage = {"v": (10, 5, 0.01)}

    def _adj(view):
        return None
    _adj.usage = lambda: usage["v"]

    class _Judge:
        _llm = _adj

    j = _Judge()
    seen = {"usd": 0.0, "in": 0, "out": 0}          # same shape as regression.py:162
    _meter_judge_llm(j, store, rid, seen)            # cumulative 0.01 -> log 0.01
    usage["v"] = (25, 12, 0.03)
    _meter_judge_llm(j, store, rid, seen)            # cumulative 0.03 -> log delta 0.02
    _meter_judge_llm(j, store, rid, seen)            # no change -> log nothing

    rows = store._conn.execute(
        "SELECT usd, input_tokens, output_tokens FROM cost_ledger ORDER BY id").fetchall()
    assert [round(r[0], 4) for r in rows] == [0.01, 0.02]      # deltas, not [0.01, 0.03]
    assert [r[1] for r in rows] == [10, 15] and [r[2] for r in rows] == [5, 7]
    store.close()


async def test_empty_regression_db_is_not_green(tmp_path, monkeypatch):
    # An empty/unmigrated exploit DB has nothing to prove fixed — the fail-closed gate
    # must report EMPTY / not-green, never silently GREEN (which would let a
    # misconfigured or unpopulated DB pass a CI merge gate).
    st = _settings(tmp_path, monkeypatch)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        result = await run_regression(settings=st)
    assert result["total"] == 0
    assert result["empty"] is True
    assert result["all_passed"] is False  # empty is NOT green


def test_full_exploit_db_scan_meets_time_slo():
    # SLO (Week_3 doc:498-501; ARCHITECTURE §7): a full scan of the exploit DB must
    # complete within a defined time budget. Populate a realistic DB and MEASURE it.
    # Budget is deliberately generous (SQLite enumerates hundreds of rows in <10ms),
    # so this is a real regression guard on the scan cost, never a flaky timing test.
    import tempfile
    import time
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        store = Store(Path(d) / "slo.sqlite")
        for i in range(500):
            store.record_exploit(ConfirmedExploit(
                exploit_id=f"ex_{i}", attempt_id="at", verdict_id="vd",
                category=AttackCategory.data_exfiltration, severity=Severity.high,
                target_invariant="INV-AUTHZ-PATIENT",
                minimal_transcript=[TranscriptTurn(role="attacker", content=f"probe-{i}")],
                expected_safe="403", observed=f"leak-{i}"))
        t0 = time.perf_counter()
        rows = store.list_exploits()          # SELECT * FROM exploits — the full scan
        elapsed = time.perf_counter() - t0
        assert len(rows) == 500               # scan really enumerated the whole DB
        assert elapsed < 2.0, f"full exploit-DB scan took {elapsed:.3f}s (budget 2.0s)"
        store.close()


def test_decide_failure_outcome_passes():
    d = _decide_case(seed_requires_auth=False, authenticated=False,
                     outcome=Outcome.failure, prev_status="open")
    assert d["result"] == "passed"
    assert d["reappeared"] is False


def test_decide_error_outcome_is_inconclusive_never_a_pass():
    # A dead/erroring target must NOT masquerade as a fix. It is neither a pass
    # (the vuln is not confirmed fixed) nor a fail (not confirmed live) — it is
    # inconclusive. Counting it as "passed" is the "worse than no test" trap.
    d = _decide_case(seed_requires_auth=False, authenticated=False,
                     outcome=Outcome.error, prev_status="resolved")
    assert d["result"] == "errored"
    assert d["reappeared"] is False


def test_decide_success_outcome_fails_and_flags_reappearance():
    d = _decide_case(seed_requires_auth=False, authenticated=True,
                     outcome=Outcome.success, prev_status="resolved")
    assert d["result"] == "failed"
    assert d["reappeared"] is True


def test_decide_success_on_still_open_exploit_is_not_a_reappearance():
    d = _decide_case(seed_requires_auth=False, authenticated=True,
                     outcome=Outcome.success, prev_status="open")
    assert d["result"] == "failed"
    assert d["reappeared"] is False


def test_decide_auth_required_no_session_skips():
    d = _decide_case(seed_requires_auth=True, authenticated=False,
                     outcome=Outcome.success, prev_status=None)
    assert d["result"] == "skipped"
    assert d["reason"] == "requires_auth"


# ── CLI/consumer contract: run_regression() must return the shape cli.regress reads ──
async def test_run_regression_returns_cli_contract_shape(tmp_path, monkeypatch):
    # Regression guard for the audit finding: the shipped `adversaryforge regress`
    # command reads result['details'] with rows {case_id, category, passed: bool,
    # note: str}, plus top-level passed/total/failed/skipped/errored/reappeared.
    st = _settings(tmp_path, monkeypatch)
    with respx.mock(assert_all_called=False) as router:  # keep it hermetic (docstring: fully offline)
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        result = await run_regression(settings=st)  # no cases stored -> empty but well-shaped
    assert result["target_version"] == "t"  # served by respx, not a swallowed live-connection 'unknown'
    for key in ("target_version", "passed", "total", "failed", "skipped",
                "errored", "reappeared", "all_passed", "details"):
        assert key in result, f"missing top-level key {key!r}"
    assert isinstance(result["details"], list)
    # Exercise the exact CLI rendering path so a shape drift fails here, not at runtime.
    for row in result["details"]:
        assert set(row) >= {"case_id", "category", "passed", "note"}
        assert isinstance(row["passed"], bool)


def test_decide_partial_outcome_is_inconclusive_never_a_pass():
    # A `partial` re-judge (confidence ~0.3, "flagged for review") is inconclusive,
    # exactly like an unreachable target — it must NOT count as a fixed vuln. This
    # is the security-relevant false-green the fail-closed gate exists to prevent.
    d = _decide_case(seed_requires_auth=False, authenticated=False,
                     outcome=Outcome.partial, prev_status=None)
    assert d["result"] == "errored"
    assert d["reappeared"] is False


# ── cross-category regression detector ──────────────────────────────────────
def test_detect_cross_category_regression_flags_risen_success():
    before = {"prompt_injection": {"success": 0, "failure": 3},
              "data_exfiltration": {"success": 1}}
    after = {"prompt_injection": {"success": 2, "failure": 1},   # rose 0 -> 2
             "data_exfiltration": {"success": 1}}                # unchanged
    assert detect_cross_category_regression(before, after) == ["prompt_injection"]


def test_detect_cross_category_regression_new_category_from_zero():
    before = {}
    after = {"denial_of_service": {"success": 1}}
    assert detect_cross_category_regression(before, after) == ["denial_of_service"]


def test_detect_cross_category_regression_none_when_flat_or_improved():
    before = {"tool_misuse": {"success": 2}}
    after = {"tool_misuse": {"success": 0}}  # improved
    assert detect_cross_category_regression(before, after) == []


# ── integration: run_regression against a respx-mocked target ────────────────
def _settings(tmp_path, monkeypatch) -> Settings:
    # Fields use validation_alias, so they populate from env, not init kwargs.
    monkeypatch.setenv("ADVERSARYFORGE_TARGET_BASE_URL", BASE)
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")   # AnonymousSession
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")           # deterministic Judge only
    monkeypatch.setenv("ADVERSARYFORGE_MIN_REQUEST_GAP_S", "0.0")
    monkeypatch.setenv("ADVERSARYFORGE_MAX_CONCURRENCY", "4")
    return Settings()


def _seed_case(store: Store, seed_id: str, exploit_id: str, invariant: str) -> None:
    store.record_regression_case(RegressionCandidate(
        case_id="rc_" + seed_id,
        exploit_id=exploit_id,
        category=AttackCategory.data_exfiltration,
        request={"seed_id": seed_id, "steps": []},
        assertion={"kind": "invariant_holds", "invariant": invariant},
        severity=Severity.critical,
    ))


def _resolved_exploit(store: Store, exploit_id: str, invariant: str) -> None:
    store.record_exploit(ConfirmedExploit(
        exploit_id=exploit_id,
        attempt_id="at_seed",
        verdict_id="vd_seed",
        category=AttackCategory.data_exfiltration,
        severity=Severity.critical,
        target_invariant=invariant,
        minimal_transcript=[TranscriptTurn(role="attacker", content="x")],
        expected_safe="403/404",
        observed="was leaking",
    ))
    store.set_exploit_status(exploit_id, "resolved")


async def test_run_regression_pass_when_defense_holds(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    # df-authz-chat-noauth: requires_auth=False, INV-AUTHZ-PATIENT, POST /v1/chat.
    _seed_case(store, "df-authz-chat-noauth", "ex_hold", "INV-AUTHZ-PATIENT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(
            return_value=Response(200, json={"version": "test-1"}))
        # 403 => authz enforced => Judge verdict failure => case PASSES.
        router.post(f"{BASE}/v1/chat").mock(return_value=Response(403, json={}))

        result = await run_regression(settings=st)

    assert result["total"] == 1
    assert result["passed"] == 1
    assert result["failed"] == 0
    assert result["all_passed"] is True
    case = result["cases"][0]
    assert case["result"] == "passed"
    assert case["outcome"] == "failure"
    # Exercise the CLI-contract 'details' row shape with a REAL populated row.
    drow = result["details"][0]
    assert set(drow) >= {"case_id", "category", "passed", "note"}
    assert drow["passed"] is True and isinstance(drow["note"], str) and drow["note"]


async def test_run_regression_errored_target_fails_closed(tmp_path, monkeypatch):
    # A dead/unreachable target yields Outcome.error -> 'errored' -> the fail-closed
    # gate is NOT green (inconclusive can never masquerade as "fixed"). Drives the
    # real run_regression path, not the all_passed arithmetic in isolation.
    import httpx
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    _seed_case(store, "df-authz-chat-noauth", "ex_err", "INV-AUTHZ-PATIENT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.post(f"{BASE}/v1/chat").mock(side_effect=httpx.ConnectError("boom"))
        result = await run_regression(settings=st)

    assert result["total"] == 1
    assert result["errored"] == 1
    assert result["passed"] == 0 and result["failed"] == 0
    assert result["all_passed"] is False
    assert result["cases"][0]["result"] == "errored"
    assert result["cases"][0]["outcome"] == "error"


async def test_run_regression_fails_and_reopens_resolved_exploit(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    _seed_case(store, "di-ready-enum", "ex_reappear", "INV-INFO-DISCLOSURE")
    _resolved_exploit(store, "ex_reappear", "INV-INFO-DISCLOSURE")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(
            return_value=Response(200, json={"version": "test-1"}))
        # /ready leaks dependency inventory to an anonymous caller =>
        # INV-INFO-DISCLOSURE success => the previously-resolved finding FAILS again.
        router.get(f"{BASE}/ready").mock(return_value=Response(
            200, json={"dependencies": {"openemr": "ok", "fhir": "ok"}, "database": "ok"}))

        result = await run_regression(settings=st)

    assert result["failed"] == 1
    assert result["passed"] == 0
    assert result["reappeared"] == 1
    assert result["all_passed"] is False
    assert result["cases"][0]["reappeared"] is True

    # The reappearance must have flipped the exploit status back to 'open'.
    store2 = Store(st.db_path)
    status = {e["exploit_id"]: e["status"] for e in store2.list_exploits()}
    store2.close()
    assert status["ex_reappear"] == "open"


async def test_run_regression_replays_the_mutated_override_payload(tmp_path, monkeypatch):
    # Anti-drift core: a mutation-discovered case must replay the MUTATED payload that
    # broke through, NOT the base seed (which was only ever a partial). Guards the
    # override_messages replay so a refactor dropping it fails loudly.
    import json as _json
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    store.record_regression_case(RegressionCandidate(
        case_id="rc_mut", exploit_id="ex_mut", category=AttackCategory.data_exfiltration,
        request={"seed_id": "df-authz-chat-noauth", "steps": [],
                 "override_messages": ["MUTATED-BREAKTHROUGH-XYZ"]},
        assertion={"kind": "invariant_holds", "invariant": "INV-AUTHZ-PATIENT"},
        severity=Severity.high))
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        chat = router.post(f"{BASE}/v1/chat").mock(return_value=Response(401, json={}))
        await run_regression(settings=st)

    sent = _json.loads(chat.calls.last.request.content)
    assert sent["message"] == "MUTATED-BREAKTHROUGH-XYZ"  # the MUTATED payload, not the base seed


async def test_expired_cookie_downgrades_to_unauthenticated_and_skips_authed(tmp_path, monkeypatch):
    # A non-empty but REJECTED cookie must not let authed cases run and false-pass on
    # a 401. run_regression probes /v1/auth/me and downgrades a dead session to unauth,
    # so authed cases SKIP (never green-on-drift).
    _settings(tmp_path, monkeypatch)  # sets data dir + BASE; cookie forced ""
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "expired-garbage-cookie")
    st = Settings()  # re-read WITH the cookie -> authed starts True
    store = Store(st.db_path)
    _seed_case(store, "pi-direct-system-prompt-reveal", "ex_auth", "INV-INJECTION-INERT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.get(f"{BASE}/v1/auth/me").mock(return_value=Response(401, json={}))  # dead session
        result = await run_regression(settings=st)

    assert result["skipped"] >= 1          # authed case skipped, not falsely passed
    assert result["passed"] == 0
    actions = {e["action"] for e in Store(st.db_path).agent_timeline(result["run_id"])}
    assert "session_expired" in actions


async def test_run_regression_skips_auth_required_case_without_session(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    # df-cross-patient-off-rounds requires_auth=True; no session -> skipped.
    _seed_case(store, "df-cross-patient-off-rounds", "ex_auth", "INV-AUTHZ-PATIENT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(
            return_value=Response(200, json={"version": "test-1"}))
        chat_route = router.post(f"{BASE}/v1/chat").mock(
            return_value=Response(200, json={"action": "served", "answer": "leak"}))

        result = await run_regression(settings=st)

    assert result["skipped"] == 1
    assert result["passed"] == 0
    assert result["failed"] == 0
    assert result["all_passed"] is True  # skipped-only run stays GREEN by design (gate ignores skips)
    assert result["cases"][0]["result"] == "skipped"
    assert result["cases"][0]["reason"] == "requires_auth"
    # Auth gate is decided WITHOUT touching the target.
    assert not chat_route.called


async def test_run_regression_unbinds_tracer_even_when_a_case_raises(tmp_path, monkeypatch):
    # use_tracer must reset the tracer contextvar on ANY exit path, including an
    # exception mid-loop. The old bare bind/unbind bracketing ran unbind only AFTER
    # the loop, so a raising case leaked the contextvar into the next run. Force a
    # raise inside the loop and assert the tracer is unbound afterwards.
    from adversaryforge.agents.judge import Judge
    from adversaryforge.observability.tracing import _current_tracer

    st = _settings(tmp_path, monkeypatch)   # trace_enabled defaults True -> a real Tracer binds
    store = Store(st.db_path)
    # df-authz-chat-noauth: requires_auth=False, POST /v1/chat -> the loop reaches the Judge.
    _seed_case(store, "df-authz-chat-noauth", "ex_boom", "INV-AUTHZ-PATIENT")
    store.close()

    def _boom(self, attempt):
        raise RuntimeError("judge blew up mid-loop")
    monkeypatch.setattr(Judge, "evaluate_attempt", _boom)

    assert _current_tracer.get() is None    # clean slate before the run
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.post(f"{BASE}/v1/chat").mock(return_value=Response(200, json={"action": "served"}))
        with pytest.raises(RuntimeError, match="blew up"):
            await run_regression(settings=st)

    assert _current_tracer.get() is None    # reset despite the exception (would leak with bind/unbind)


async def test_run_regression_skips_case_whose_seed_is_missing(tmp_path, monkeypatch):
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    _seed_case(store, "no-such-seed-id", "ex_missing", "INV-AUTHZ-PATIENT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(
            return_value=Response(200, json={"version": "test-1"}))
        result = await run_regression(settings=st)

    assert result["skipped"] == 1
    assert result["cases"][0]["reason"] == "seed_not_found"
