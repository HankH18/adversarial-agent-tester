"""Platform wiring — assemble the agents and run a campaign end-to-end.

This is the seam where the multi-agent system actually runs: Orchestrator selects,
Red Team executes, Judge evaluates (behind the info barrier), the harness records,
and everything lands in the observability store. Designed to run with or without an
LLM key and with or without a live session — degrading, never crashing.
"""
from __future__ import annotations

from dataclasses import dataclass

from adversaryforge.agents.judge import Judge
from adversaryforge.agents.orchestrator import Orchestrator
from adversaryforge.config import Settings, get_settings
from adversaryforge.contracts import Outcome
from adversaryforge.observability.store import Store
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

        by_outcome: dict[str, int] = {}
        successes = 0
        mutations_run = 0
        halted = False
        exploits_before = _count_exploits(store)
        for seed in runnable:
            _, verdict = await orch.run_seed(seed, directive or _fallback_directive(seed),
                                             executor, judge, run_id,
                                             mutator=mutator, n_variants=n_variants)
            out = _enum(verdict.outcome)
            by_outcome[out] = by_outcome.get(out, 0) + 1
            if verdict.outcome == Outcome.success:
                successes += 1
            elif verdict.outcome == Outcome.partial and mutator is not None:
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

        cost = store.cost_summary(run_id)["usd"]
        store.end_run(run_id, cost)
        exploits_new = _count_exploits(store) - exploits_before

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
    )


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
