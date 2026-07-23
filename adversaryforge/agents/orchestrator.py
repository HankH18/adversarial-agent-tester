"""Orchestrator Agent — the strategist.

Two responsibilities, deliberately split by trust:
  * **Target selection is deterministic.** Which category the Red Team hits next is
    a scoring policy over the observability substrate (coverage gaps, open
    high-severity findings, recent regressions) — never an LLM guess. This is
    auditable and reproducible.
  * **Rationale is prose.** An LLM (when available) writes the human-readable
    "why this campaign now"; if no key, a deterministic template fills in.

It also owns the campaign loop: drive the Red Team executor, hand each attempt to
the Judge (behind the info barrier), record verdicts, and promote confirmed
successes into the exploit DB + regression suite. The cost governor can halt a
campaign that burns budget without producing signal.
"""
from __future__ import annotations

import uuid

from adversaryforge.agents.judge import Judge
from adversaryforge.contracts import (
    AttackAttempt,
    CampaignDirective,
    ConfirmedExploit,
    Outcome,
    RegressionCandidate,
    Verdict,
)
from adversaryforge.observability.store import Store
from adversaryforge.observability.tracing import trace
from adversaryforge.redteam.executor import SeedExecutor
from adversaryforge.redteam.seeds import Seed, SeedLibrary


# Base priority when there is no signal yet — reflects threat-model ranking.
_CATEGORY_BASE_PRIORITY = {
    "prompt_injection": 5.0,
    "data_exfiltration": 5.0,
    "state_corruption": 4.0,
    "identity_role": 4.0,
    "denial_of_service": 3.0,
    "tool_misuse": 3.0,
}


class Orchestrator:
    def __init__(self, store: Store, library: SeedLibrary) -> None:
        self._store = store
        self._library = library
        # Cumulative Judge-LLM usage already written to the cost ledger (so we log
        # only the delta after each evaluation, never double-count).
        self._judge_cost = {"usd": 0.0, "in": 0, "out": 0}

    def _meter_judge_llm(self, judge: Judge, run_id: str) -> None:
        """Write the Judge's LLM-adjudicator spend delta into the cost ledger, so
        `status`, the cost analysis, and the cost governor all see real spend."""
        adj = getattr(judge, "_llm", None)
        usage = getattr(adj, "usage", None) if adj is not None else None
        if usage is None:
            return
        in_t, out_t, usd = usage()
        d_usd = usd - self._judge_cost["usd"]
        if d_usd > 1e-9:
            self._store.log_cost(run_id, "judge", "adjudicator",
                                 in_t - self._judge_cost["in"],
                                 out_t - self._judge_cost["out"], d_usd)
            self._judge_cost = {"usd": usd, "in": in_t, "out": out_t}

    # ── deterministic target selection ─────────────────────────────────────
    def score_categories(self, *, authenticated: bool) -> list[tuple[str, float, str]]:
        """Return (category, score, reason) sorted desc. Higher = attack sooner.

        Signal: base threat priority + a coverage-gap bonus (few attempts) + an
        open-findings bonus (a category with open exploits deserves mutation
        pressure) − a saturation penalty (well-covered, all-defended)."""
        # campaign_only: exclude regression-replay runs so `regress` can't shift the
        # deterministic target selection (keeps selection reproducible/auditable).
        coverage = self._store.coverage_by_category(campaign_only=True)
        passfail = self._store.passfail_rates(campaign_only=True)
        open_by_cat: dict[str, int] = {}
        for ex in self._store.list_exploits(status="open"):
            open_by_cat[ex["category"]] = open_by_cat.get(ex["category"], 0) + 1

        runnable_cats = {
            _enum(s.category) for s in self._library.runnable(authenticated=authenticated)
        }
        scored: list[tuple[str, float, str]] = []
        for cat in runnable_cats:
            base = _CATEGORY_BASE_PRIORITY.get(cat, 3.0)
            attempts = coverage.get(cat, 0)
            gap_bonus = 3.0 if attempts == 0 else max(0.0, 2.0 - attempts * 0.1)
            open_bonus = min(3.0, open_by_cat.get(cat, 0) * 1.0)
            successes = passfail.get(cat, {}).get("success", 0)
            total = sum(passfail.get(cat, {}).values())
            saturation = -1.0 if (total >= 8 and successes == 0) else 0.0
            score = base + gap_bonus + open_bonus + saturation
            reason = (f"base={base:.0f} gap+{gap_bonus:.1f} open+{open_bonus:.0f} "
                      f"sat{saturation:+.0f} (attempts={attempts}, open={open_by_cat.get(cat,0)})")
            scored.append((cat, round(score, 2), reason))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def next_directive(self, *, authenticated: bool) -> CampaignDirective | None:
        scored = self.score_categories(authenticated=authenticated)
        if not scored:
            return None
        cat, score, reason = scored[0]
        seeds = [s for s in self._library.runnable(authenticated=authenticated)
                 if _enum(s.category) == cat]
        invariant = seeds[0].target_invariant if seeds else ""
        return CampaignDirective(
            directive_id="dir_" + uuid.uuid4().hex[:10],
            category=cat,
            rationale=f"Selected {cat} (score {score}): {reason}. "
                      f"{len(seeds)} runnable seed(s).",
            target_invariant=invariant,
            max_attempts=max(1, len(seeds)),
            seed_ids=[s.id for s in seeds],
        )

    # ── campaign execution ──────────────────────────────────────────────────
    async def run_seed(
        self, seed: Seed, directive: CampaignDirective, executor: SeedExecutor,
        judge: Judge, run_id: str, mutator=None, n_variants: int = 8,
    ) -> tuple[AttackAttempt, Verdict]:
        with trace("orchestrator.run_seed", "orchestrator", seed=seed.id,
                   category=_enum(seed.category), invariant=seed.target_invariant) as sp:
            attempt = await executor.run(seed, directive.directive_id)
            self._store.record_attempt(run_id, attempt)
            self._store.log_event(run_id, "redteam", "attempt", f"{seed.id} ({_enum(seed.category)})")

            verdict = judge.evaluate_attempt(attempt)  # info barrier applied inside
            self._meter_judge_llm(judge, run_id)
            self._store.record_verdict(run_id, verdict)
            self._store.log_event(run_id, "judge", "verdict",
                                  f"{seed.id} -> {_enum(verdict.outcome)} ({_enum(verdict.severity)})")
            sp.update(outcome=_enum(verdict.outcome), severity=_enum(verdict.severity),
                      method=verdict.method)

            if verdict.outcome == Outcome.success:
                self._promote(seed, attempt, verdict, run_id)
            elif verdict.outcome == Outcome.partial and mutator is not None:
                # A partial is a foothold: autonomously generate N variants to probe
                # for a version that breaks through (the core Red Team behavior).
                await self._mutate_and_run(seed, attempt, verdict, directive, executor,
                                           judge, run_id, mutator, n_variants)
            return attempt, verdict

    async def _mutate_and_run(self, seed, parent, verdict, directive, executor,
                              judge, run_id, mutator, n) -> None:
        base_messages = self._seed_messages(seed)
        if not base_messages:
            return  # nothing message-bearing to mutate (e.g. pure HTTP probe)
        with trace("redteam.mutate", "redteam", seed=seed.id, n=n,
                   trigger="partial") as msp:
            self._store.log_event(run_id, "redteam", "mutate",
                                  f"{seed.id}: partial → generating {n} variants")
            before_cost = getattr(mutator, "cost_usd", 0.0) or 0.0
            variants = await mutator.mutate(base_messages, seed.target_invariant,
                                            verdict.rationale, n=n)
            msp.set("variants_generated", len(variants))
            # Log only THIS mutation's spend (cost_usd is cumulative on the mutator).
            delta = (getattr(mutator, "cost_usd", 0.0) or 0.0) - before_cost
            if delta > 1e-9:
                self._store.log_cost(run_id, "redteam", getattr(mutator, "_model", "redteam"),
                                     0, 0, delta)
            breakthroughs = 0
            for i, variant in enumerate(variants):
                with trace("redteam.variant", "redteam", index=i, generation=1) as vsp:
                    child = await executor.run(seed, directive.directive_id, generation=1,
                                               parent_attempt_id=parent.attempt_id,
                                               override_messages=variant)
                    self._store.record_attempt(run_id, child)
                    cv = judge.evaluate_attempt(child)
                    self._meter_judge_llm(judge, run_id)
                    self._store.record_verdict(run_id, cv)
                    self._store.log_event(run_id, "judge", "verdict",
                                          f"{seed.id}#mut{i} → {_enum(cv.outcome)}")
                    vsp.set("outcome", _enum(cv.outcome))
                    if cv.outcome == Outcome.success:
                        breakthroughs += 1
                        self._store.log_event(run_id, "redteam", "mutation_breakthrough",
                                              f"{seed.id}#mut{i} broke through after a partial")
                        self._promote(seed, child, cv, run_id, override_messages=variant)
            msp.set("breakthroughs", breakthroughs)

    @staticmethod
    def _seed_messages(seed: Seed) -> list[str]:
        """Messages to mutate, one per step — only when EVERY step is a message-
        bearing chat turn (direct, multi-turn, persona injections). Seeds with HTTP
        or upload steps are skipped: mutating a non-message step is meaningless."""
        msgs: list[str] = []
        for step in seed.steps:
            if step.kind == "chat" and step.message:
                msgs.append(step.message)
            else:
                return []
        return msgs

    def _promote(self, seed: Seed, attempt: AttackAttempt, verdict: Verdict, run_id: str,
                 override_messages: list[str] | None = None) -> None:
        exploit = ConfirmedExploit(
            exploit_id="ex_" + uuid.uuid4().hex[:12],
            attempt_id=attempt.attempt_id,
            verdict_id=verdict.verdict_id,
            category=attempt.category,
            subcategory=attempt.subcategory,
            severity=verdict.severity,
            target_invariant=attempt.target_invariant,
            minimal_transcript=attempt.transcript,
            expected_safe=attempt.expected_safe,
            observed=verdict.rationale,
            owasp_web=attempt.owasp_web,
            owasp_llm=attempt.owasp_llm,
            target_version=self._target_version(run_id),
        )
        inserted = self._store.record_exploit(exploit)
        if not inserted:
            self._store.log_event(run_id, "judge", "dedupe",
                                  f"exploit for {seed.id} already known — skipped")
            return
        self._store.log_event(run_id, "judge", "exploit_confirmed",
                              f"{exploit.exploit_id} sev={_enum(verdict.severity)}")
        if seed.add_to_regression:
            request: dict = {"seed_id": seed.id, "steps": [s.model_dump() for s in seed.steps]}
            # For a mutation-discovered exploit, freeze the MUTATED payload that
            # actually broke through — replaying the base seed (which was only a
            # partial) would falsely report the vuln as fixed and never detect it.
            if override_messages is not None:
                request["override_messages"] = override_messages
            case = RegressionCandidate(
                case_id="rc_" + uuid.uuid4().hex[:10],
                exploit_id=exploit.exploit_id,
                category=attempt.category,
                request=request,
                assertion={"kind": "invariant_holds", "invariant": attempt.target_invariant},
                severity=verdict.severity,
            )
            self._store.record_regression_case(case)
            self._store.log_event(run_id, "harness", "regression_added", case.case_id)

    def _target_version(self, run_id: str) -> str:
        r = self._store._conn.execute(  # noqa: SLF001 - internal read
            "SELECT target_version FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return r["target_version"] if r else "unknown"


def _enum(v) -> str:
    return v.value if hasattr(v, "value") else str(v)
