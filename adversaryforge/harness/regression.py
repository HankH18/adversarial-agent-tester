"""Regression & Validation Harness — replay confirmed exploits, re-judge invariants.

Every confirmed exploit is frozen into a `RegressionCandidate` (the seed steps plus
the invariant it falsified). This harness re-executes each case against the current
target and re-adjudicates it with the **same deterministic, invariant-based Judge**
that confirmed it. A case *passes* iff the re-judged outcome is no longer
`success` — i.e. the invariant is no longer falsifiable.

Why re-judging with the same invariant Judge matters
----------------------------------------------------
The case study's sharpest warning is: *"a test that passes because behavior changed
is worse than no test."* A naive regression test snapshots the model's *answer* and
asserts equality; it then goes green the moment the model phrases things
differently — a wording change, a refusal template swap, a temperature wobble — even
though the underlying vulnerability is untouched. That green is a lie.

We avoid this by construction:

  * The Judge never compares strings-to-a-snapshot. It evaluates a **named
    invariant** (`INV-AUTHZ-PATIENT`, `INV-WITHHOLD-UNGROUNDED`, …) against
    machine-checkable signals — HTTP status, the `action`/`withheld` sentinel, a
    planted canary, latency budgets. These are *properties of the security
    contract*, not properties of a particular phrasing.
  * The Judge is deterministic-first and versioned (`RULESET_VERSION`). The exact
    same logic that scored the exploit `success` scores the replay. If the replay
    now scores `failure`, the invariant genuinely cannot be violated by that
    sequence any more — the answer being differently worded is *irrelevant* to the
    verdict, because the verdict was never about the wording.

So a PASS here means: *the defensive property is now enforced*, not *the model said
something new*. That is the whole point — the test cannot go green on drift, only on
a real fix. Conversely a FAIL means the invariant is falsifiable again: the vuln is
still open, or (a reappearance) a previously-`resolved` exploit is back.

Degrade-never-crash: runs with no ANTHROPIC_API_KEY (deterministic Judge only) and
with no session cookie (auth-required cases are SKIPPED, never scored). A dead
target yields `Outcome.error` from the Judge, which is *not* `success`, so an
unreachable target never masquerades as a fix — it simply cannot confirm one, and
error cases are reported distinctly rather than counted as passes.
"""
from __future__ import annotations

from typing import Any

from adversaryforge.agents.judge import Judge
from adversaryforge.config import Settings, get_settings
from adversaryforge.contracts import Outcome
from adversaryforge.observability.store import Store
from adversaryforge.observability.tracing import Tracer, bind_tracer, unbind_tracer
from adversaryforge.platform import build_llm_adjudicator
from adversaryforge.redteam.executor import SeedExecutor
from adversaryforge.redteam.seeds import SeedLibrary
from adversaryforge.target.adapter import agentforge_adapter
from adversaryforge.target.client import TargetClient
from adversaryforge.target.session import build_session

# Exploit statuses that, if re-judged `success`, count as a *reappearance*
# (a previously closed-out finding is live again).
_RESOLVED_STATUSES = {"resolved", "fixed"}


def _enum(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)


async def _target_version(client: TargetClient) -> str:
    resp = await client.request("GET", "/health")
    j = resp.json
    if isinstance(j, dict) and j.get("version"):
        return str(j["version"])
    return "unknown"


def _decide_case(
    *,
    seed_requires_auth: bool,
    authenticated: bool,
    outcome: Outcome | str,
    prev_status: str | None,
) -> dict[str, Any]:
    """Pure decision core (no I/O) — the harness's testable contract.

    Returns a dict with ``result`` in {"skipped","passed","failed","errored"} and a
    ``reappeared`` flag. A case PASSES iff the re-judged outcome is ``failure`` (the
    invariant held / the fix is real). It FAILS if outcome == ``success`` (the vuln
    is still open). An ``error`` outcome (target unreachable/malformed) is
    **inconclusive — never a pass**: counting a dead target as "fixed" is exactly
    the "a test that passes because behavior changed is worse than no test" trap.
    Auth-required cases with no session are SKIPPED (neither pass nor fail).
    """
    if seed_requires_auth and not authenticated:
        return {"result": "skipped", "reason": "requires_auth", "reappeared": False}

    val = _enum(outcome)
    if val == Outcome.success.value:
        reappeared = (prev_status or "").lower() in _RESOLVED_STATUSES
        return {"result": "failed", "reason": "invariant_falsified", "reappeared": reappeared}
    if val == Outcome.failure.value:
        return {"result": "passed", "reason": "invariant_holds", "reappeared": False}
    # partial OR error is INCONCLUSIVE — never a green on drift. A `partial`
    # (Judge confidence ~0.3, "flagged for review") is the same class as an
    # unreachable target: we cannot confirm the fix, so the fail-closed gate
    # treats it as errored, exactly like the error path.
    reason = "inconclusive_target_error" if val == Outcome.error.value else "inconclusive_partial"
    return {"result": "errored", "reason": reason, "reappeared": False}


async def run_regression(*, settings: Settings | None = None) -> dict[str, Any]:
    """Re-run every stored regression case and re-judge its invariant.

    Wires Settings/adapter/session/Store/SeedLibrary/Judge/TargetClient exactly as
    ``platform.run_campaign`` does, then for each ``RegressionCandidate``:
      * locates its seed by ``case.request['seed_id']``;
      * SKIPS it if the seed ``requires_auth`` and no session is configured;
      * otherwise re-executes the seed via ``SeedExecutor`` and re-judges via
        ``Judge.evaluate_attempt``;
      * PASS iff the outcome is not ``success``; FAIL if it is;
      * on a FAIL whose exploit was previously ``resolved``, records a
        *reappearance* and flips that exploit's status back to ``open``.

    Returns a summary dict with per-case details. Never raises on a missing key or
    dead target — it degrades.
    """
    settings = settings or get_settings()
    adapter = agentforge_adapter(settings.target_base_url)
    session = build_session(settings)
    store = Store(settings.db_path)
    library = SeedLibrary.load()
    judge = Judge(llm_adjudicator=build_llm_adjudicator(settings))
    authed = session.is_authenticated

    seed_by_id = {s.id: s for s in library.seeds}
    # ConfirmedExploit (get_exploit) carries no status column; status is a
    # DB-level field, read here as a map from the exploits table.
    status_by_exploit = {e["exploit_id"]: e.get("status") for e in store.list_exploits()}

    cases = store.list_regression_cases()

    passed = failed = skipped = reappeared = errored = 0
    details: list[dict[str, Any]] = []

    async with TargetClient(adapter, session, settings) as client:
        version = await _target_version(client)
        # A non-empty cookie is not the same as a LIVE session. If the configured
        # cookie is expired/invalid, every authed request 401s, which the Judge maps
        # to "defense held" -> a false "fix confirmed". Probe liveness and downgrade a
        # dead session to unauthenticated so its cases SKIP rather than green on drift.
        session_downgraded = False
        if authed and not await _session_live(client):
            authed = False
            session_downgraded = True
        run_id = store.start_run(
            settings.target_base_url, version, "regression", authed,
            notes=f"regression cases={len(cases)}",
        )
        if session_downgraded:
            store.log_event(run_id, "harness", "session_expired",
                            "configured cookie rejected by the target; authed cases skipped")

        executor = SeedExecutor(client)
        _trace_token = bind_tracer(Tracer(store, run_id) if settings.trace_enabled else None)
        _judge_seen = {"usd": 0.0, "in": 0, "out": 0}  # cumulative Judge-LLM spend metered
        passfail_before = store.passfail_rates()  # snapshot for cross-category regression

        for case in cases:
            seed_id = (case.request or {}).get("seed_id")
            seed = seed_by_id.get(seed_id)
            base = {
                "case_id": case.case_id,
                "exploit_id": case.exploit_id,
                "seed_id": seed_id,
                "category": _enum(case.category),
                "severity": _enum(case.severity),
                "invariant": (case.assertion or {}).get("invariant"),
            }

            if seed is None:
                skipped += 1
                store.log_event(run_id, "harness", "regression_skipped",
                                f"{case.case_id}: seed '{seed_id}' not in library")
                details.append({**base, "result": "skipped", "reason": "seed_not_found",
                                "reappeared": False, "outcome": None, "rationale": None})
                continue

            prev_status = status_by_exploit.get(case.exploit_id)
            decision = _decide_case(
                seed_requires_auth=seed.requires_auth,
                authenticated=authed,
                outcome=Outcome.failure,  # placeholder; overwritten after real judge
                prev_status=prev_status,
            )

            # Auth gate is decided WITHOUT touching the target.
            if decision["result"] == "skipped":
                skipped += 1
                store.log_event(run_id, "harness", "regression_skipped",
                                f"{case.case_id}: requires auth, no session")
                details.append({**base, "result": "skipped", "reason": "requires_auth",
                                "reappeared": False, "outcome": None, "rationale": None})
                continue

            # Replay the frozen sequence and re-adjudicate the invariant. For a
            # mutation-discovered case, replay the exact mutated payload that broke
            # through (not the base seed), or the case can never re-detect the vuln.
            overrides = (case.request or {}).get("override_messages")
            attempt = await executor.run(seed, directive_id="regression",
                                         override_messages=overrides)
            verdict = judge.evaluate_attempt(attempt)
            # Record into the store so the after-snapshot (and cross-category
            # detection) actually reflect this run. Attempt before verdict:
            # record_verdict/passfail join on attempt_id.
            store.record_attempt(run_id, attempt)
            store.record_verdict(run_id, verdict)
            _meter_judge_llm(judge, store, run_id, _judge_seen)  # LLM spend -> cost ledger
            outcome = verdict.outcome

            decision = _decide_case(
                seed_requires_auth=seed.requires_auth,
                authenticated=authed,
                outcome=outcome,
                prev_status=prev_status,
            )

            row = {**base, "result": decision["result"], "reason": decision["reason"],
                   "reappeared": decision["reappeared"], "outcome": _enum(outcome),
                   "rationale": verdict.rationale}

            result = decision["result"]
            if result == "passed":
                passed += 1
                store.log_event(run_id, "harness", "regression_pass",
                                f"{case.case_id}: invariant holds ({_enum(outcome)})")
            elif result == "failed":
                failed += 1
                store.log_event(run_id, "harness", "regression_fail",
                                f"{case.case_id}: invariant falsified again")
                if decision["reappeared"]:
                    reappeared += 1
                    store.set_exploit_status(case.exploit_id, "open")
                    store.log_event(run_id, "harness", "regression_reappeared",
                                    f"{case.exploit_id}: was '{prev_status}', reopened")
            else:  # errored — inconclusive, fail-closed for the gate
                errored += 1
                store.log_event(run_id, "harness", "regression_errored",
                                f"{case.case_id}: inconclusive ({verdict.rationale[:60]})")

            details.append(row)

        # Cross-category regression: did fixing/replaying push any OTHER category's
        # success count up? Exclude the categories we exercised this run — a replayed
        # still-open case writes a fresh success verdict for its OWN category, which is
        # not a cross-category effect. (A true cross-category signal needs a
        # cross-VERSION comparison; within one replay window this is ~always empty.)
        exercised = {r["category"] for r in details if r["result"] != "skipped"}
        cross_category = [c for c in
                          detect_cross_category_regression(passfail_before, store.passfail_rates())
                          if c not in exercised]
        if cross_category:
            store.log_event(run_id, "harness", "cross_category_regression",
                            f"success rose in: {', '.join(cross_category)}")

        unbind_tracer(_trace_token)
        store.end_run(run_id, store.cost_summary(run_id)["usd"])

    # CLI-contract view: the published shape the caller (cli.regress) and any
    # consumer relies on — {case_id, category, passed: bool, note: str}.
    cli_details = [
        {
            "case_id": r["case_id"],
            "category": r["category"],
            "passed": r["result"] == "passed",
            "result": r["result"],  # passed|failed|skipped|errored (superset of contract)
            "note": (r.get("rationale") or r.get("reason") or r["result"]),
        }
        for r in details
    ]
    return {
        "run_id": run_id,
        "target_version": version,
        "authenticated": authed,
        "total": len(cases),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errored": errored,
        "reappeared": reappeared,
        # CI gate is FAIL-CLOSED: green only when zero live failures AND zero
        # inconclusive (errored) cases. A dead/unreachable target yields errors,
        # which must NOT read as "everything is fixed". Skips (auth/missing seed)
        # are explicitly out of scope and don't fail the gate.
        "all_passed": failed == 0 and errored == 0,
        "cross_category_regressions": cross_category,  # categories whose success rose
        "details": cli_details,  # CLI/consumer contract
        "cases": details,        # rich internal rows
    }


async def _session_live(client) -> bool:
    """True only if the configured session is one the target actually accepts."""
    try:
        resp = await client.request("GET", "/v1/auth/me")
    except Exception:
        return False
    return resp.status_code == 200


def _meter_judge_llm(judge, store, run_id: str, seen: dict) -> None:
    """Write the Judge adjudicator's LLM spend delta into the cost ledger (mirrors
    Orchestrator._meter_judge_llm), so regression runs meter real spend too."""
    adj = getattr(judge, "_llm", None)
    usage = getattr(adj, "usage", None) if adj is not None else None
    if usage is None:
        return
    in_t, out_t, usd = usage()
    d_usd = usd - seen["usd"]
    if d_usd > 1e-9:
        store.log_cost(run_id, "judge", "adjudicator", in_t - seen["in"], out_t - seen["out"], d_usd)
        seen.update(usd=usd, **{"in": in_t, "out": out_t})


def detect_cross_category_regression(before: dict, after: dict) -> list[str]:
    """Flag categories whose *success* count rose between two passfail snapshots.

    A "passfail snapshot" is the shape returned by ``Store.passfail_rates()``:
    ``{category: {outcome: count}}``. A rising success count in some category after
    a change elsewhere is the classic *fixing-one-thing-broke-another* signal —
    a cross-category regression the harness must surface even when the targeted
    category improved.

    Returns the sorted list of category names whose success count increased.
    """
    regressed: list[str] = []
    for category, outcomes in (after or {}).items():
        after_succ = int((outcomes or {}).get(Outcome.success.value, 0) or 0)
        before_succ = int((before or {}).get(category, {}).get(Outcome.success.value, 0) or 0)
        if after_succ > before_succ:
            regressed.append(category)
    return sorted(regressed)
