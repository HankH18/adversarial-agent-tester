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
    AttackAttempt,
    AttackCategory,
    ConfirmedExploit,
    Outcome,
    RegressionCandidate,
    Severity,
    TranscriptTurn,
    Verdict,
)
from adversaryforge.harness.regression import (
    _decide_case,
    _previous_version,
    detect_cross_category_regression,
    detect_cross_version_regression,
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


async def test_full_regression_scan_meets_time_slo(tmp_path, monkeypatch):
    # SLO (Week_3 doc:498-501; ARCHITECTURE §7): a full regression scan must complete
    # within a defined time budget. The OLD test timed a bare `list_exploits()` SELECT —
    # NOT the scan the SLO is about. This measures the REAL path: load every regression
    # case, replay its seed through the throttled TargetClient, re-judge the invariant,
    # and record attempt+verdict — the whole replay+re-judge loop `run_regression` runs.
    # Budget has generous headroom for slow CI (30 cases replay+re-judge in <0.1s
    # locally), so it is a real regression guard on scan cost, never a flaky timing test.
    import time

    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    n_cases = 30
    for i in range(n_cases):
        # df-authz-chat-noauth: requires_auth=False → every case actually replays.
        # Distinct case_id per iteration (record_regression_case keys on case_id).
        store.record_regression_case(RegressionCandidate(
            case_id=f"rc_slo_{i}", exploit_id=f"ex_slo_{i}",
            category=AttackCategory.data_exfiltration,
            request={"seed_id": "df-authz-chat-noauth", "steps": []},
            assertion={"kind": "invariant_holds", "invariant": "INV-AUTHZ-PATIENT"},
            severity=Severity.high))
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        chat = router.post(f"{BASE}/v1/chat").mock(return_value=Response(403, json={}))
        t0 = time.perf_counter()
        result = await run_regression(settings=st)
        elapsed = time.perf_counter() - t0

    assert result["total"] == n_cases          # the whole DB was scanned
    assert result["passed"] == n_cases         # each case really replayed + re-judged
    assert chat.called                          # the replay hit the target, not a stub
    assert len(chat.calls) == n_cases           # one replay per case — no work skipped
    assert elapsed < 5.0, f"full regression scan took {elapsed:.3f}s (budget 5.0s)"


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


# ── cross-VERSION regression detector (the LIVE-wired signal) ────────────────
def test_detect_cross_version_regression_fires_on_genuine_regression():
    # prompt_injection was PASSING at the prior version (0 successes) and is now FAILING
    # (1 success) WHILE data_exfiltration was being fixed (successes fell 2 -> 0). That is
    # the fixing-one-thing-broke-another pattern → prompt_injection is flagged.
    before = {"data_exfiltration": {"success": 2, "failure": 1},
              "prompt_injection": {"success": 0, "failure": 3}}
    after = {"data_exfiltration": {"success": 0, "failure": 3},   # fixed
             "prompt_injection": {"success": 1, "failure": 2}}    # regressed
    assert detect_cross_version_regression(before, after) == ["prompt_injection"]


def test_detect_cross_version_regression_silent_when_nothing_being_fixed():
    # prompt_injection rose 0 -> 1, but NOTHING else was being remediated → this is an
    # ordinary newly-found bug, not a cross-fix regression → no flag (no false-fire).
    before = {"data_exfiltration": {"success": 2}, "prompt_injection": {"success": 0}}
    after = {"data_exfiltration": {"success": 2}, "prompt_injection": {"success": 1}}
    assert detect_cross_version_regression(before, after) == []


def test_detect_cross_version_regression_silent_when_all_improved():
    # Everything got better across the bump → nothing flipped passing→failing → no flag.
    before = {"data_exfiltration": {"success": 2}, "prompt_injection": {"success": 1}}
    after = {"data_exfiltration": {"success": 0}, "prompt_injection": {"success": 0}}
    assert detect_cross_version_regression(before, after) == []


def test_detect_cross_version_regression_ignores_brand_new_category():
    # A category absent at the prior version was never "passing" there — a success at the
    # current version is not a regression-from-passing, so it must NOT be flagged even
    # though something else was being fixed.
    before = {"data_exfiltration": {"success": 2}}
    after = {"data_exfiltration": {"success": 0},                 # fixed
             "prompt_injection": {"success": 1}}                  # brand new, not a regression
    assert detect_cross_version_regression(before, after) == []


def _record_outcome(store: Store, version: str, category: AttackCategory,
                    outcome: Outcome, sev: Severity = Severity.high) -> None:
    """Record one attempt+verdict under a run tagged with ``version`` so
    passfail_rates(target_version=version) reflects it — how run_regression feeds the
    cross-version comparison."""
    import uuid
    rid = store.start_run("http://t", version, "authenticated", True)
    aid = "at_" + uuid.uuid4().hex[:8]
    store.record_attempt(rid, AttackAttempt(
        attempt_id=aid, directive_id="d", category=category,
        target_invariant="INV-X", expected_safe="safe",
        transcript=[TranscriptTurn(role="attacker", content="x")]))
    store.record_verdict(rid, Verdict(
        verdict_id="vd_" + uuid.uuid4().hex[:8], attempt_id=aid, outcome=outcome,
        severity=sev, confidence=0.9, rationale="r"))
    store.end_run(rid, 0.0)


def test_cross_version_regression_fires_across_two_stored_versions(tmp_path):
    # Store REAL verdicts under TWO target versions, then run the exact comparison
    # run_regression performs: _previous_version + passfail_rates(target_version=…) +
    # detect_cross_version_regression.
    #   v1: data_exfiltration vuln live (success),   prompt_injection held (failure).
    #   v2: data_exfiltration FIXED (failure),       prompt_injection now regressed (success).
    # → prompt_injection is flagged (fixing exfil broke injection).
    store = Store(tmp_path / "xv.sqlite")
    _record_outcome(store, "v1", AttackCategory.data_exfiltration, Outcome.success)
    _record_outcome(store, "v1", AttackCategory.prompt_injection, Outcome.failure)
    _record_outcome(store, "v2", AttackCategory.data_exfiltration, Outcome.failure)
    _record_outcome(store, "v2", AttackCategory.prompt_injection, Outcome.success)

    assert _previous_version(store, "v2") == "v1"
    before = store.passfail_rates(target_version=_previous_version(store, "v2"))
    after = store.passfail_rates(target_version="v2")
    assert detect_cross_version_regression(before, after) == ["prompt_injection"]

    # Negative: a v3 where BOTH categories now hold (nothing flips passing→failing) must
    # NOT false-fire even though prompt_injection was being fixed (v2 success → v3 none).
    _record_outcome(store, "v3", AttackCategory.data_exfiltration, Outcome.failure)
    _record_outcome(store, "v3", AttackCategory.prompt_injection, Outcome.failure)
    assert _previous_version(store, "v3") == "v2"
    before3 = store.passfail_rates(target_version=_previous_version(store, "v3"))
    after3 = store.passfail_rates(target_version="v3")
    assert detect_cross_version_regression(before3, after3) == []
    store.close()


def test_previous_version_none_when_only_current_recorded(tmp_path):
    # A single-version history has no prior baseline → cross-version check is skipped.
    store = Store(tmp_path / "one.sqlite")
    _record_outcome(store, "only", AttackCategory.data_exfiltration, Outcome.success)
    assert _previous_version(store, "only") is None
    store.close()


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


async def test_regression_pass_resolves_the_exploit(tmp_path, monkeypatch):
    # A passing regression (the invariant now HOLDS) marks the exploit 'resolved' — the
    # wiring that makes reappearance reachable if a later run re-falsifies it. (Before
    # this, nothing set 'resolved', so the reappearance path was dead code.)
    st = _settings(tmp_path, monkeypatch)
    store = Store(st.db_path)
    store.record_exploit(ConfirmedExploit(
        exploit_id="ex_fixable", attempt_id="at", verdict_id="vd",
        category=AttackCategory.data_exfiltration, severity=Severity.critical,
        target_invariant="INV-AUTHZ-PATIENT",
        minimal_transcript=[TranscriptTurn(role="attacker", content="x")],
        expected_safe="401", observed="was leaking"))
    _seed_case(store, "df-authz-chat-noauth", "ex_fixable", "INV-AUTHZ-PATIENT")
    store.close()
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.post(f"{BASE}/v1/chat").mock(return_value=Response(401, json={}))  # defense holds → pass
        result = await run_regression(settings=st)
    assert result["passed"] >= 1
    ex = {e["exploit_id"]: e for e in Store(st.db_path).list_exploits()}["ex_fixable"]
    assert ex["status"] == "resolved"  # pass auto-resolves → reappearance now reachable


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


async def test_run_regression_runs_authed_case_with_live_session(tmp_path, monkeypatch):
    # AUTH THREADING: with a configured, LIVE session cookie, a requires_auth regression
    # case must actually RUN — replayed WITH the session — not be unconditionally skipped.
    # Regression guard for the audit finding "N skipped despite a valid cookie": the
    # harness threads build_session(settings) into the TargetClient replay path exactly
    # like platform.py, and recognizes a live session via /v1/auth/status.
    _settings(tmp_path, monkeypatch)               # sets data dir + BASE; cookie forced ""
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "valid-physician-cookie")
    st = Settings()                                # re-read WITH the cookie → authed starts True
    store = Store(st.db_path)
    # pi-direct-system-prompt-reveal: requires_auth=True, POST /v1/chat.
    _seed_case(store, "pi-direct-system-prompt-reveal", "ex_authed", "INV-INJECTION-INERT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        # LIVE session: the canonical unauthenticated probe reports the cookie resolves.
        router.get(f"{BASE}/v1/auth/status").mock(
            return_value=Response(200, json={"auth_mode": "smart", "authenticated": True}))
        chat = router.post(f"{BASE}/v1/chat").mock(return_value=Response(403, json={}))
        result = await run_regression(settings=st)

    assert result["authenticated"] is True
    assert result["skipped"] == 0                  # the requires_auth case was NOT skipped
    assert result["cases"][0]["result"] != "skipped"
    assert chat.called                              # it actually replayed against the target
    # The replay carried the configured session cookie, wrapped in the target's cookie NAME
    # (`af_session=<value>`) — a bare value is not parsed by the target, which is the exact
    # bug that made every "authenticated" request 401. Threaded via TargetClient.
    assert chat.calls.last.request.headers.get("cookie") == "af_session=valid-physician-cookie"


async def test_run_regression_authed_case_via_auth_me_fallback(tmp_path, monkeypatch):
    # Robustness: if /v1/auth/status doesn't confirm (unavailable on a deployment), a 200
    # from the authenticated identity endpoint /v1/auth/me still proves the cookie is live,
    # so the authed case runs instead of being wrongly downgraded to skipped.
    _settings(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "valid-physician-cookie")
    st = Settings()
    store = Store(st.db_path)
    _seed_case(store, "pi-direct-system-prompt-reveal", "ex_authed2", "INV-INJECTION-INERT")
    store.close()

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={"version": "t"}))
        router.get(f"{BASE}/v1/auth/status").mock(          # doesn't confirm liveness
            return_value=Response(200, json={"authenticated": False}))
        router.get(f"{BASE}/v1/auth/me").mock(              # but the cookie IS accepted
            return_value=Response(200, json={"clinician_id": 1}))
        chat = router.post(f"{BASE}/v1/chat").mock(return_value=Response(403, json={}))
        result = await run_regression(settings=st)

    assert result["authenticated"] is True
    assert result["skipped"] == 0
    assert chat.called


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
