"""Platform wiring — assemble the agents and run a campaign end-to-end.

This is the seam where the multi-agent system actually runs: Orchestrator selects,
Red Team executes, Judge evaluates (behind the info barrier), the harness records,
and everything lands in the observability store. Designed to run with or without an
LLM key and with or without a live session — degrading, never crashing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from adversaryforge.agents.calibration import calibrate_judge
from adversaryforge.agents.judge import Judge
from adversaryforge.agents.orchestrator import Orchestrator
from adversaryforge.config import Settings, get_settings
from adversaryforge.contracts import Outcome
from adversaryforge.observability.store import Store
from adversaryforge.observability.tracing import Tracer, use_tracer
from adversaryforge.redteam.executor import SeedExecutor
from adversaryforge.redteam.seeds import Seed, SeedLibrary
from adversaryforge.target.adapter import agentforge_adapter
from adversaryforge.target.client import TargetClient
from adversaryforge.target.session import build_session


@dataclass
class CampaignResult:
    run_id: str
    target_version: str
    authenticated: bool
    total: int
    successes: int
    by_outcome: dict[str, int]
    exploits_new: int
    directive_rationale: str
    mutations_run: int = 0
    halted_no_signal: bool = False
    calibration_kappa: float | None = None
    calibration_passed: bool = True


def should_halt_no_signal(spent_usd: float, budget_usd: float, confirmed: int) -> bool:
    """Cost governor: halt a campaign that is burning budget without producing
    signal. True iff a positive budget is set, spend has reached it, and not one
    exploit has been confirmed. Disabled when budget <= 0."""
    return budget_usd > 0 and spent_usd >= budget_usd and confirmed == 0


def build_mutator(settings: Settings):
    """A Mutator is always available — it has a deterministic (keyless) fallback, so
    the mutation loop runs with or without an ANTHROPIC_API_KEY."""
    try:
        from adversaryforge.llm.mutator import Mutator

        return Mutator(settings)
    except Exception:
        return None


async def _target_version(client: TargetClient) -> str:
    resp = await client.request("GET", "/health")
    j = resp.json
    if isinstance(j, dict) and j.get("version"):
        return str(j["version"])
    return "unknown"


def build_llm_adjudicator(settings: Settings):
    """Return a JudgeView->(Outcome,conf,rationale) callable if a key is set, else None.
    Kept import-light so the platform never hard-depends on the Anthropic SDK path."""
    if not settings.has_llm:
        return None
    try:
        from adversaryforge.llm.judge_llm import make_llm_adjudicator

        return make_llm_adjudicator(settings)
    except Exception:
        return None


async def run_campaign(
    *,
    settings: Settings | None = None,
    categories: list[str] | None = None,
    sweep: bool = True,
    limit: int | None = None,
    mutate: bool = True,
    n_variants: int = 8,
) -> CampaignResult:
    settings = settings or get_settings()
    adapter = agentforge_adapter(settings.target_base_url)
    session = build_session(settings)
    store = Store(settings.db_path)
    library = SeedLibrary.load()
    orch = Orchestrator(store, library)
    judge = Judge(llm_adjudicator=build_llm_adjudicator(settings))
    mutator = build_mutator(settings) if mutate else None
    authed = session.is_authenticated

    async with TargetClient(adapter, session, settings) as client:
        version = await _target_version(client)
        mode = "authenticated" if authed else "unauthenticated"
        run_id = store.start_run(settings.target_base_url, version, mode, authed,
                                 notes=f"seeds={len(library.seeds)}")

        # ── Judge drift gate ─────────────────────────────────────────────────
        # Calibrate the Judge against the frozen gold set BEFORE attacking. If Cohen's
        # kappa falls below the threshold the Judge has drifted and its verdicts can't
        # be trusted, so the campaign FAILS CLOSED rather than record findings we can't
        # stand behind. (Set ADVERSARYFORGE_JUDGE_KAPPA_THRESHOLD=0 to disable.)
        cal = calibrate_judge(judge, settings.judge_kappa_threshold)
        store.log_event(run_id, "judge", "calibration",
                        f"kappa={cal.kappa} passed={cal.passed} "
                        f"({cal.agreements}/{cal.n} gold cases, threshold {cal.threshold})")
        if not cal.passed:
            store.log_event(run_id, "judge", "calibration_halt",
                            f"Judge drift: kappa {cal.kappa} < {cal.threshold}; "
                            f"disagreements={cal.disagreements}")
            store.end_run(run_id, store.cost_summary(run_id)["usd"])
            return CampaignResult(
                run_id=run_id, target_version=version, authenticated=authed, total=0,
                successes=0, by_outcome={}, exploits_new=0,
                directive_rationale="halted: Judge failed calibration (drift gate)",
                calibration_kappa=cal.kappa, calibration_passed=False)

        executor = SeedExecutor(client)

        directive = orch.next_directive(authenticated=authed)
        rationale = directive.rationale if directive else "no runnable seeds"

        # Which seeds to run this campaign.
        runnable = library.runnable(authenticated=authed)
        if categories:
            runnable = [s for s in runnable if _enum(s.category) in set(categories)]
        elif not sweep and directive is not None:
            runnable = [s for s in runnable if s.id in set(directive.seed_ids)]
        if limit:
            runnable = runnable[:limit]
        # Persist the ordered plan so a crashed run can resume EXACTLY these seeds.
        store.log_event(run_id, "orchestrator", "plan", json.dumps([s.id for s in runnable]))

        by_outcome, successes, mutations_run, halted, exploits_new = await _drive_seeds(
            store, orch, runnable, directive, executor, judge, run_id, settings, mutator, n_variants)
        cost = store.cost_summary(run_id)["usd"]
        store.end_run(run_id, cost)

    return CampaignResult(
        run_id=run_id,
        target_version=version,
        authenticated=authed,
        total=len(runnable),
        successes=successes,
        by_outcome=by_outcome,
        exploits_new=exploits_new,
        directive_rationale=rationale,
        mutations_run=mutations_run,
        halted_no_signal=halted,
        calibration_kappa=cal.kappa,
        calibration_passed=True,
    )


async def _drive_seeds(store, orch, seeds, directive, executor, judge, run_id,
                       settings, mutator, n_variants):
    """Run each seed through the Judge, tallying outcomes under the cost governor.
    Shared by run_campaign and resume_campaign so both paths behave identically.
    Returns (by_outcome, successes, mutations_run, halted, exploits_new)."""
    by_outcome: dict[str, int] = {}
    successes = 0
    mutations_run = 0
    halted = False
    exploits_before = _count_exploits(store)
    tracer = Tracer(store, run_id) if settings.trace_enabled else None
    with use_tracer(tracer):
        for seed in seeds:
            _, verdict = await orch.run_seed(seed, directive or _fallback_directive(seed),
                                             executor, judge, run_id,
                                             mutator=mutator, n_variants=n_variants)
            out = _enum(verdict.outcome)
            by_outcome[out] = by_outcome.get(out, 0) + 1
            if verdict.outcome == Outcome.success:
                successes += 1
            elif (verdict.outcome == Outcome.partial and mutator is not None
                  and Orchestrator._seed_messages(seed)):  # only counts real mutations
                mutations_run += 1

            # Cost governor: stop burning budget once it produces no signal.
            spent = store.cost_summary(run_id)["usd"]
            confirmed = _count_exploits(store) - exploits_before
            if should_halt_no_signal(spent, settings.nosignal_halt_usd, confirmed):
                store.log_event(run_id, "orchestrator", "cost_halt",
                                f"no-signal halt: ${spent:.4f} >= budget "
                                f"${settings.nosignal_halt_usd:.2f}, 0 confirmed exploits")
                halted = True
                break
    return by_outcome, successes, mutations_run, halted, _count_exploits(store) - exploits_before


async def resume_campaign(run_id: str | None = None, *, settings: Settings | None = None,
                          n_variants: int = 8) -> CampaignResult:
    """Resume a crashed/interrupted campaign under its ORIGINAL run_id, continuing
    exactly the planned seeds that don't yet have a recorded verdict. This is native
    durable-checkpoint resume: no run restarts from zero. With run_id=None, resumes the
    most recent incomplete run (`ended_at IS NULL`)."""
    settings = settings or get_settings()
    store = Store(settings.db_path)
    rid = run_id or store.latest_incomplete_run()
    if rid is None:
        raise ValueError("no incomplete run to resume")
    run = store.get_run(rid)
    if run is None:
        raise ValueError(f"unknown run_id {rid!r}")
    authed = bool(run.get("authenticated"))
    if run.get("ended_at"):
        return CampaignResult(run_id=rid, target_version=run.get("target_version") or "unknown",
                              authenticated=authed, total=0, successes=0, by_outcome={},
                              exploits_new=0, directive_rationale="run already complete")

    adapter = agentforge_adapter(settings.target_base_url)
    session = build_session(settings)
    library = SeedLibrary.load()
    orch = Orchestrator(store, library)
    judge = Judge(llm_adjudicator=build_llm_adjudicator(settings))
    mutator = build_mutator(settings)

    # Reconstruct the ORIGINAL plan (persisted at start) and skip completed seeds.
    plan = store.get_run_plan(rid) or [s.id for s in library.runnable(authenticated=authed)]
    done = store.completed_seeds(rid)
    by_id = {s.id: s for s in library.seeds}
    pending = [by_id[sid] for sid in plan if sid in by_id and sid not in done]

    async with TargetClient(adapter, session, settings) as client:
        version = await _target_version(client)
        executor = SeedExecutor(client)
        directive = orch.next_directive(authenticated=authed)
        store.log_event(rid, "orchestrator", "resume",
                        f"{len(done)} of {len(plan)} seeds already complete; continuing {len(pending)}")
        by_outcome, successes, mutations_run, halted, exploits_new = await _drive_seeds(
            store, orch, pending, directive, executor, judge, rid, settings, mutator, n_variants)
        store.end_run(rid, store.cost_summary(rid)["usd"])

    return CampaignResult(
        run_id=rid, target_version=version, authenticated=authed, total=len(pending),
        successes=successes, by_outcome=by_outcome, exploits_new=exploits_new,
        directive_rationale=f"resumed run {rid}: {len(done)} done, {len(pending)} remaining",
        mutations_run=mutations_run, halted_no_signal=halted)


def seed_demo(*, settings: Settings | None = None) -> dict:
    """Populate the store with a few ILLUSTRATIVE confirmed findings + regression cases
    under a mode='demo' run, so a FRESH CLONE can immediately exercise
    status / regress / report / trace WITHOUT a live campaign (the most impressive parts
    otherwise show empty until a live run). Uses REAL seed ids so `regress` can actually
    replay them; idempotent (record_exploit dedupes); mode='demo' is excluded from
    target-selection metrics so it never skews a real campaign."""
    from adversaryforge.contracts import (
        AttackAttempt,
        ConfirmedExploit,
        RegressionCandidate,
        Severity,
        TranscriptTurn,
        Verdict,
    )

    settings = settings or get_settings()
    store = Store(settings.db_path)
    by_id = {s.id: s for s in SeedLibrary.load().seeds}
    demo = [
        ("dos-rate-limit-absence", Severity.medium,
         "No throttling across 12 rapid requests (no 429) — rate limiting absent. [demo]"),
        ("di-ready-enum", Severity.low,
         "Anonymous 200 discloses internal state: dependencies, openemr, langfuse. [demo]"),
        ("di-openapi-exposed", Severity.low,
         "Anonymous 200 exposes the full OpenAPI contract to unauthenticated callers. [demo]"),
    ]
    run_id = store.start_run(settings.target_base_url, "demo", "demo", False,
                             notes="seed-demo: illustrative findings, not a live run")
    written = 0
    for i, (sid, sev, observed) in enumerate(demo):
        seed = by_id.get(sid)
        if seed is None:
            continue
        transcript = [TranscriptTurn(role="attacker", content=f"[demo] probe: {sid}"),
                      TranscriptTurn(role="target", content=observed, http_status=200)]
        attempt = AttackAttempt(
            attempt_id=f"demo_at_{i}", directive_id="demo", seed_id=seed.id,
            category=seed.category, subcategory=seed.subcategory,
            target_invariant=seed.target_invariant, expected_safe=seed.expected_safe,
            owasp_web=seed.owasp_web, owasp_llm=seed.owasp_llm, transcript=transcript)
        verdict = Verdict(
            verdict_id=f"demo_vd_{i}", attempt_id=attempt.attempt_id, outcome=Outcome.success,
            severity=sev, confidence=0.85, method="deterministic", rationale=observed,
            invariant_violated=seed.target_invariant, is_regression_candidate=True)
        store.record_attempt(run_id, attempt)
        store.record_verdict(run_id, verdict)
        exploit = ConfirmedExploit(
            exploit_id=f"ex_demo{i:08d}", attempt_id=attempt.attempt_id,
            verdict_id=verdict.verdict_id, category=seed.category, subcategory=seed.subcategory,
            severity=sev, target_invariant=seed.target_invariant, minimal_transcript=transcript,
            expected_safe=seed.expected_safe, observed=observed,
            owasp_web=seed.owasp_web, owasp_llm=seed.owasp_llm, target_version="demo")
        if store.record_exploit(exploit):
            written += 1
            store.record_regression_case(RegressionCandidate(
                case_id=f"rc_demo{i}", exploit_id=exploit.exploit_id, category=seed.category,
                request={"seed_id": seed.id, "steps": [s.model_dump() for s in seed.steps]},
                assertion={"kind": "invariant_holds", "invariant": seed.target_invariant},
                severity=sev))
    store.end_run(run_id, 0.0)
    return {"run_id": run_id, "findings": written}


def _count_exploits(store: Store) -> int:
    return store._conn.execute("SELECT COUNT(*) n FROM exploits").fetchone()["n"]  # noqa: SLF001


def _fallback_directive(seed: Seed):
    from adversaryforge.contracts import CampaignDirective

    return CampaignDirective(
        directive_id="dir_sweep", category=seed.category,
        rationale="full sweep", target_invariant=seed.target_invariant,
    )


def _enum(v) -> str:
    return v.value if hasattr(v, "value") else str(v)
