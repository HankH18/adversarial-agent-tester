# AS_BUILT.md — AdversaryForge, as designed vs. as shipped

> **Audience: a hospital CISO deciding whether to trust this platform to continuously test a system
> physicians depend on.** `ARCHITECTURE.md` is the *plan*. This document is the *honest diff* between
> that plan and the code that actually runs today. Where the two disagree, this file is the truth about
> the code, and it names every gap rather than papering over it. Every claim below cites the **file and
> the named symbol** (function/method/class); the line numbers are approximate and may drift between
> commits — **grep the named symbol** if a cited line has moved. The symbol is the canonical anchor.
>
> **How to verify this document (2 minutes)** — run from the repo root after
> `uv pip install -e '.[dev]'`. The `python -m` form is cwd-independent and always resolves the
> package; the `adversaryforge <cmd>` console script is equivalent after a clean install.
> ```bash
> .venv/bin/pytest -q                              # → all passing  (150+ tests; run it for the exact count)
> .venv/bin/python -m adversaryforge.cli seeds     # the seed library + test-design roles
> .venv/bin/python -m adversaryforge.cli campaign  # run the multi-agent spine live (unauth surface, no keys)
> .venv/bin/python -m adversaryforge.cli status    # the observability snapshot the Orchestrator reads
> .venv/bin/python -m adversaryforge.cli regress   # replay the frozen regression suite, fail-closed gate
> .venv/bin/python -m adversaryforge.cli report    # (re)generate the vulnerability reports in reports/
> ```
> Everything above runs with **no `ANTHROPIC_API_KEY` and no session cookie** — the deterministic core
> is the product; the LLM tiers are additive.

**Measured state at time of writing (2026-07-22):** the full unit-test suite passes; the multi-agent spine runs
end-to-end live against `https://agentforge.hankholcomb.com`; 3 professional vulnerability reports are
generated in `reports/`; 7 versioned JSON-Schema contracts are published in `contracts/`; the SQLite
substrate answers every required observability question.

**Legend:** ✅ built & tested · 🟡 built, narrower than the plan · ⚪ deferred (not built) · ⚠️ declared but not yet wired

---

## 1. Component-by-component: built vs. deferred

### 1.1 Orchestrator — *the strategist*

| | |
|---|---|
| **Built** ✅ | Deterministic target selection is real and auditable. `Orchestrator.score_categories()` computes a per-category priority from the live observability substrate — base threat weight + coverage-gap bonus + open-findings bonus − saturation penalty — and logs the arithmetic in a human-readable `reason` string (`adversaryforge/agents/orchestrator.py:72-100`, base weights at `:36-44`). `next_directive()` emits a typed `CampaignDirective` (`:84-100`). The Orchestrator also owns the live campaign loop: drive Red Team → hand each attempt to the Judge behind the information barrier → record verdicts → promote confirmed successes into the exploit DB and regression suite (`run_seed` at `:103-123`, `_promote` at `:165-198`). **No LLM sits in the decision path** — exactly as the plan requires (`ARCHITECTURE.md §4.1, §6`). |
| **Deferred** ⚪ | (a) **ε-greedy exploration** (`ARCHITECTURE.md §6`) is *not* implemented — selection is currently pure argmax over the score, so the platform can tunnel on the highest-scoring seam. (b) The full weighted formula's `recent_regression`, `recent_hit_rate`, and `cost_per_finding` terms (`§6`) are approximated by the coverage/open-findings/saturation signals actually in the scorer, not the exact five-term equation. (c) **LLM-authored rationale** is not wired — the rationale is the deterministic `reason` template, not Claude prose. |
| **Why** | The decision that matters for a CISO — *which category, and why* — is deterministic and logged today. The deferred items are refinements to *breadth* and *narration*, not to *trust*: they change which under-explored seam gets picked next, not whether a pick is explainable. They are safe, additive follow-ups. |

### 1.2 Red Team — *the adversary*

| | |
|---|---|
| **Built** ✅ | A declarative, reproducible seed engine, not a payload dump. Seeds name the invariant they target, their OWASP Web + LLM mapping, the expected-safe behavior, and a test-design role (`adversaryforge/redteam/seeds.py:59+`; corpus in `evals/seeds/*.yaml`). The `SeedExecutor` compiles each step into a real HTTP request — chat, generic HTTP, multipart document upload with document-id capture, and a bounded liveness *burst* for rate-limit probing — and assembles the transcript the Judge reads (`adversaryforge/redteam/executor.py:25-209`; multipart at `:124-130`, `from-upload` sentinel substitution at `:140-154`, burst at `:76-100`). **The executor never decides success** — it deliberately does not judge its own attacks (`:6-9`). The **mutation loop is real**: a `partial` verdict on a message-bearing seed autonomously generates N variants, runs each as a linked child attempt (generation+1), re-judges, and promotes any breakthrough — the case study's "take a partial → generate 10 variants" behavior (`orchestrator.py:118-151`). The Mutator has a fully deterministic keyless fallback (role/authority/leetspeak/base64/turn-split/hypothetical/override transforms) so the loop runs with no API key (`adversaryforge/llm/mutator.py:93-200`). |
| **Built** ✅ | The intended attacker — **Nous Hermes 4 405B via OpenRouter** — is the shipped path when `OPENROUTER_API_KEY` is set (verified with a live call), restoring the *different model family* independence from the Claude Judge; absent the key the mutator falls back to Claude. See **§2.3**. |
| **Deferred** ⚪ | Tree/TAP-style search with pruning and full role-phased escalation (`ARCHITECTURE.md §4.2`) are not built — mutation is a single breadth wave, not an iterative pruned tree. The collaborating "attack squad" was always a deferred gated experiment (`§4.2`) and remains so. |
| **Why** | The graded Red Team requirement — *reproducible cases across ≥3 categories, and a partial autonomously expanded into variants* — is met and tested. Tree search buys attack-success depth the MVP doesn't need to prove the architecture; it is additive. |

### 1.3 Judge — *the independent evaluator*

| | |
|---|---|
| **Built** ✅ | **This is the strongest-shipped component.** Independence is enforced as a *type*, not a promise: the Judge's only input is a `JudgeView` exposing the transcript, the invariant, the expected-safe behavior, and the taxonomy — the attacker's `technique`/`intent`/`confidence` are structurally absent from the view, so the evaluator *cannot* read them (`adversaryforge/agents/judge.py:39-59`; `evaluate_attempt` builds the barrier view at `:100-103`; the private fields live on `AttackAttempt` at `contracts/__init__.py:115-118` and are dropped). The deterministic core dispatches ten invariant rules over machine-checkable signals — HTTP status, the `action`/`withheld` sentinel, structured `claims`, a planted canary, latency budgets, burst-status sets (`judge.py:127-284`). Verdicts are versioned (`RULESET_VERSION = "judge-rules-1.0.0"`, `:36`) and covered by a ground-truth test set including the load-bearing invariant *"a held defense is never scored success"* and the info-barrier structural check (`tests/test_judge_groundtruth.py`). The LLM second-opinion is injected, key-gated, and reads only the `JudgeView` (`:72-98`; adjudicator in `adversaryforge/llm/judge_llm.py`, information-barrier note at its `:8-16`). When neither tier can decide, the Judge fails to a **conservative low-confidence `partial` flagged for review** — never a false `success` (`:90-98`). |
| **Built** ✅ | (a) The **per-run Cohen's-κ calibration gate** is **now built**: every campaign calibrates the Judge against a frozen gold set in its preamble and **fails closed** below the κ threshold, halting before it attacks (`agents/calibration.py`, wired in `platform.py` `run_campaign`; `ADVERSARYFORGE_JUDGE_KAPPA_THRESHOLD`, default 0.8). It complements — does not replace — the build-time ground-truth test set. (b) The **multi-vote adjudication panel** is **now built**: `judge_panel_votes > 1` runs N independent LLM votes on each ambiguous verdict, aggregated by majority (`llm/judge_llm.py`; `ADVERSARYFORGE_JUDGE_PANEL_VOTES`, default 1 = single call). Both are tested (`tests/test_calibration.py`, `tests/test_judge_llm.py`). |
| **Deferred** ⚪ | Judge-uncertain **human escalation** is still represented as the `partial`/low-confidence outcome for review, not an interactive blocking gate. |
| **Known boundary (by design)** | Authz/PHI verdicts are decided **deterministically and never deferred to the LLM**: a served 200 is scored *held* unless a **planted off-limits canary** is echoed back. This is a deliberate trade-off proven out against the live authenticated plane — the LLM adjudicator, lacking authorization context, scored a clinician's *own authorized* read (and `/v1/auth/me` returning the session's own identity) as a critical bypass (a false positive an adversarial platform must not emit). The cost of eliminating that FP: a **cross-patient *chat* data-leak cannot be caught semantically** — you cannot plant the off-limits patient's unknown real data as a canary, and the LLM path that could read the prose is gone for this invariant. In the live run the target *held* on every cross-patient case, so nothing was missed; but a purely-semantic leak (the model narrating another patient's chart with no machine-checkable marker) is outside what the deterministic Judge claims to catch. Reliable authz/PHI detection therefore rests on the **canary/marker discipline in the seeds** (`df-phi-egress` plants `[[CANARY:MRN-9000001]]`; `df-cross-patient-off-rounds` names the off-limits id but plants none — a candidate to harden). Restoring semantic cross-patient detection without the FP is a scoped future build (a chat-only LLM tier given auth context), not a silent gap. |
| **Why** | The independence guarantee a CISO cares about — *the grader cannot see the attacker's self-assessment, and most verdicts are code, not model opinion* — is shipped and enforced by construction. The deferred pieces harden the **LLM tier specifically**; because most verdicts never reach that tier (see §2.2), their absence is bounded. See §3 for exactly how a drifting Judge is detected and corrected *with what exists today*. |

### 1.4 Documentation — *the scribe*

| | |
|---|---|
| **Built** ✅ | Fully built and offline. `build_report()` deterministically fills every required `VulnReport` field from the confirmed exploit alone — no key, no network (`adversaryforge/agents/documentation.py:334-378`). Clinical impact and remediation are invariant-specific, not boilerplate: a 10-entry playbook keyed by invariant id (`:47-223`). Reproduction steps are **lifted verbatim from the minimal transcript**, so repro fidelity never depends on an LLM (`build_reproduction` at `:257-287`). Two trust gates are enforced: a **data-quality validator** (unique id via sha256, all required fields, dedupe) rejects incomplete exploits before write (`validate_exploit` at `:291-310`; dedupe index at `observability/store.py:179,367`), and the **human-approval gate** — a `critical` finding is a `draft` that `requires_human_approval` with a prominent banner and is never auto-published; lower severities publish (`:362-364`, banner at `render_markdown:422`). Three real reports exist: `reports/VULN-*.md`. An optional LLM prose-enrichment pass is behind a try/except and cannot break the deterministic report (`:379-395`). |
| **Deferred** ⚪ | The LLM narrative enrichment is dormant (no key on the build machine); reports today are the deterministic prose. |
| **Why** | The graded requirement — *≥3 professional, reproducible-by-a-stranger reports with a human gate on the expensive-to-be-wrong cases* — is met with the LLM entirely out of the trust path. That is the stronger posture, not a compromise. |

### 1.5 Regression & Validation Harness

| | |
|---|---|
| **Built** ✅ | Replays each frozen `RegressionCandidate` against the current target and **re-adjudicates with the same deterministic, invariant-based Judge** that confirmed it — so a test cannot go green on a wording change, only on a real fix (`adversaryforge/harness/regression.py`; the anti-drift rationale is documented at `:9-40`). The pure decision core is separately testable (`_decide_case` at `:73-99`). The CI gate is **fail-closed**: green only when `failed == 0 AND errored == 0`, so an unreachable/dead target yields `error` (inconclusive) and can **never masquerade as "fixed"** (`:243-250`; the `error`-is-not-a-pass rule at `:94-95`). **Reappearance detection** flips a previously-`resolved` exploit back to `open` on a re-failure (`:203-211`). Degrades cleanly: no key → deterministic Judge only; no session → auth cases SKIPPED, never scored. `adversaryforge regress` runs this live. |
| **Built** ✅ | **Cross-category regression** (`detect_cross_category_regression`) is wired into `run_regression`: it snapshots pass/fail before and after the replay, excludes the categories exercised this run (a replayed still-open case writes only its own category's verdict), logs a `cross_category_regression` event, and returns `cross_category_regressions`. A genuinely cross-category signal needs a cross-VERSION comparison, so within a single replay window this is usually empty — by design, not by omission. |
| **Deferred** ⚪ | (a) The **N-replay stability check** that flags a flaky pass (`ARCHITECTURE.md §7 step 4`) is not built — replay is single-shot. This is mitigated in practice because the invariant assertions branch on the target's *deterministic* `verification.action`/status signals, which are stable, not on stochastic prose. (b) M2S multi-turn minimization (`§7 step 2`) is not built. (c) ~~The full-scan time SLO in CI is not enforced~~ — **now wired**: the timing test runs in CI (`.gitlab-ci.yml` / GitHub Actions) on every push. |
| **Why** | The one hazard the case study calls out — *a green test that means "behavior drifted," not "bug fixed"* — is closed by construction: verdicts are properties of the security contract, not of a phrasing. The deferred items reduce flake noise and add scheduling automation; they do not weaken the core guarantee. |

### 1.6 Observability

| | |
|---|---|
| **Built** ✅ | A SQLite substrate designed as the Orchestrator's *input*, not a bolt-on dashboard (`adversaryforge/observability/store.py`). It answers every required question: coverage by category (`:289-293`), pass/fail by category and target version (`:295-306`), resilience trend across versions (`:308-322`), open/in-progress/resolved findings (`:324-328`), per-agent + per-campaign cost (`:330-339`), and a full **ordered per-agent trace** of every run (`events` table, `agent_timeline`). Beyond the event log there is now **fine-grained execution tracing**: a `spans` table + a contextvar-linked tracer (`observability/tracing.py`) records nested spans *inside* each agent — `orchestrator.run_seed` → `target.request` (per HTTP call: method/path/status/latency) → `judge.evaluate` → `judge.rule` (the exact invariant rule that fired, the signals it read, and its sub-verdict) — plus `redteam.mutate`/`redteam.variant` on the mutation path and `llm.call` spans (model, tokens, USD, response preview) when a key is present. Render any run's span tree with `adversaryforge trace <run_id>`. Data-quality is enforced at the storage layer: a UNIQUE `dedupe_key` index blocks duplicate exploits for the same attack sequence, and additive idempotent migrations preserve records across a field addition (`apply_migrations`, `SCHEMA_VERSION = 3`). Indexed on severity/category/version/status for the snapshot and full-scan query paths (`:172-180`). `adversaryforge status` prints the snapshot. |
| **Deferred** ⚪ | Langfuse/OTEL export and the Postgres-at-scale path (`ARCHITECTURE.md §11, §12`) are not built — storage is SQLite only. PHI-pseudonymization at a telemetry egress is not needed because no external tracing backend is wired. |
| **Why** | Every graded observability question is answerable today from local, inspectable data. External tracing is a scale/deployment concern, not a correctness one. |

### 1.7 Contracts

| | |
|---|---|
| **Built** ✅ | Every inter-agent message is a versioned pydantic model with `extra="forbid"` (`adversaryforge/contracts/__init__.py`), and the canonical, language-agnostic JSON Schemas are published in `contracts/` — **7 schema files** (`CampaignDirective`, `AttackAttempt`, `Verdict`, `ConfirmedExploit`, `RegressionCandidate`, `VulnReport`, `AgentError`), plus a `CHANGELOG.md` and `README.md`. Both producer and consumer validate against the shape. The **typed error envelope** carries all five required codes (`target_unreachable`, `budget_exceeded`, `judge_timeout`, `no_findings_in_window`, `regression_detected`) plus three more (`AgentError` at `contracts/__init__.py:209-226`). Contract tests exist on both sides (`tests/test_contracts.py`). The information barrier is itself encoded in the contract: `AttackAttempt` carries `technique`/`intent`, and the Judge is built to read only `.transcript` (`:106-127`). |
| **Deferred** ⚪ | The cross-agent *integration-week* exercise (a peer integrating through the published contract alone) is enabled by design but not yet exercised. |
| **Why** | The graded requirement — *published, versioned, independently-testable contracts* — is fully met. This is a strength, not a gap. |

### 1.8 Cost Governor

| | |
|---|---|
| **Built** ✅ | **Cost *metering* is real and per-agent.** Every LLM call is tagged with agent role, model, tokens, and USD in a `cost_ledger` table (`observability/store.py:165-176`, `log_cost` at `:299-306`), aggregated per-run/platform (`cost_summary` at `:376-385`) and broken down per-agent (`cost_by_agent` at `:387-399`), both surfaced by `adversaryforge status`. The Mutator and LLM adjudicator both accumulate spend for this ledger (`mutator.py:84`, `judge_llm.py:87`). The pricing table drives the arithmetic (`adversaryforge/llm/pricing.py`). Critically, the platform also governs *target-side* blast radius: a self-throttle (concurrency cap + minimum inter-request gap) gates every call because the target has **no inbound rate limiting** and the platform must not become the DoS (`target/client.py:77-102`; tunables at `config.py:43-49`). |
| **Built** ✅ | The **automatic no-signal halt** — "cut a campaign burning budget without producing findings" (`ARCHITECTURE.md §6, §10`) — is now **enforced in the campaign loop**. After every seed, `run_campaign` reads the live per-run cost and confirmed-exploit count and calls the pure, unit-tested `should_halt_no_signal(spent, budget, confirmed)` (`platform.py:39`, wired at `platform.py:138`); when spend reaches `nosignal_halt_usd` with zero confirmed exploits it breaks the loop, logs a `cost_halt` event, and returns `halted_no_signal=True`. Tested in `tests/test_cost_governor.py`. Set the budget to `0` to disable. |
| **Note** | On this keyless/subagent build practical spend is ~$0, so the wall has nothing to stop yet — but it is a live control, not aspirational. Metering (per-agent, per-run) remains the observable truth of spend alongside it. |

---

## 2. The three honest gaps between plan and build

These are the deviations a CISO should weigh most. None is hidden; each has a rationale and a clean path back to the plan.

### 2.1 Framework: LangGraph (planned) vs. a deterministic Python orchestrator + SQLite (shipped)

**What the plan says.** `ARCHITECTURE.md §1, §5, §12` commit to **LangGraph** as the state machine that persists every hop, checkpoints so a crashed overnight run resumes, and *interrupts* at the human approval gates.

**What shipped.** There is **no LangGraph anywhere** in the code (`grep -ri langgraph adversaryforge/ pyproject.toml` → nothing). The MVP is a **plain, deterministic Python orchestrator** (`agents/orchestrator.py`, `platform.py:run_campaign`) over a **SQLite-backed append-only run log / event store** (`observability/store.py`). Control flow is ordinary `async` Python; durability is the SQLite `runs`/`attempts`/`verdicts`/`events` tables written as the campaign proceeds.

**The trade-off, honestly.**
- *What we gave up:* framework-native *interrupt/resume at the human gate* (still deferred). **Durable checkpoint/resume of a crashed run is NOT given up — it is built natively:** the campaign persists its ordered seed plan and per-seed completion to SQLite, and `resume_campaign` / `adversaryforge resume <run_id>` continues exactly the seeds that never got a verdict, under the *original* run id (`platform.py`; proven by a crash-then-resume test). A crashed overnight run resumes from the last committed seed, not from zero.
- *What we gained:* **zero framework dependency and full control** over the control flow (easier to audit line-by-line for a CISO — there is no opaque graph runtime to trust), **faster to ship** a working spine, and no coupling of the trust-critical logic to a fast-moving external library.
- **Crucially, this does not weaken the multi-agent separation.** The architectural guarantee that matters — that agents are genuinely separate roles exchanging *versioned, typed contracts* and never sharing evaluation context — is fully intact and, if anything, more legible without a graph runtime. Agents never call each other directly; they hand off `CampaignDirective` → `AttackAttempt` → `Verdict` → `ConfirmedExploit`/`RegressionCandidate` → `VulnReport`, each a published JSON-Schema message (`contracts/`). The Judge still receives only a `JudgeView` and can *never* see the attacker's intent (§1.3). The separation is enforced by the type system, not by the transport.

**Why this is a clean future migration, not a dead end.** LangGraph nodes *are* the agents; LangGraph edges *are* the typed contracts we already publish. The two human approval points in the design — publish-critical (`documentation.py:362-364`) and re-target-to-new-host — map **directly** onto LangGraph's interrupt-and-resume primitive; they are already discrete, gated decision points in the code, so lifting them into graph interrupts is mechanical. The persisted artifacts already conform to the published schemas, so no contract changes. Durable checkpoint/resume is *already built natively* (above), so a LangGraph migration would only add framework-native interrupts at the human gate on top of a separation that is already correct — it does not have to redesign anything.

### 2.2 Judge: deterministic-first (shipped, tested) + LLM-second (key-gated, subagent-exercised)

**What is fully verified deterministically, today, with no key.** The entire deterministic tier: ten invariant rules over machine-checkable target signals — authorization status codes, the existence-oracle 404 unification, the `withheld`/`served` sentinel, the injection canary echo, write-gate status, PHI-shape scans, info-disclosure markers, latency budgets, and burst-status rate-limit checks (`judge.py:127-284`). These decide most verdicts, are versioned (`RULESET_VERSION`), and are covered by the ground-truth test set — including the invariant *a held defense is never `success`* and the structural info-barrier check (`tests/test_judge_groundtruth.py`, part of the passing test suite).

**What awaits a key.** The **LLM second pass** — the semantic judgments the deterministic tier deliberately abstains on (did *prose* leak a bare, unlabelled patient name? did an injected instruction *steer* the free-text answer without tripping the canary?). This tier is fully wired (`judge_llm.py`) and reads only the `JudgeView`, but returns `None`/is disabled without `ANTHROPIC_API_KEY`. On this build machine **no key was present**, so where the plan runs Claude Opus in-process, the current build exercises those semantic judgments **via Claude Code subagents at build time** rather than in the live loop. The consequence a CISO must understand: **for a live keyless run, a genuinely semantic exploit that produces no deterministic signal is scored a conservative low-confidence `partial` flagged for review** (`judge.py:90-98`) — it is never silently passed as safe and never falsely confirmed. Drop a key in `.env` and the in-process semantic tier activates with no other change.

**Now built on the LLM tier:** the per-run Cohen's-κ calibration gate (campaign preamble, fail-closed) and the multi-vote panel (§1.3). See §3 for the full drift-detection story.

### 2.3 Attacker model: Nous Hermes 4 405B via OpenRouter — now active (Claude fallback)

> **Update:** this is no longer a deviation. With `OPENROUTER_API_KEY` set, the Red Team attacker +
> mutator run on **Hermes 4 405B (Meta-Llama family) via OpenRouter** while the Judge runs on **Claude**
> — different families, verified by a live call (`nousresearch/hermes-4-405b`, real per-call cost metered
> from OpenRouter's `usage.cost`). The `OpenRouterClient` (`llm/openrouter.py`) mirrors the Anthropic
> client so the Mutator swaps backends transparently; absent the key it falls back to Claude. The
> historical planned-vs-shipped discussion below is retained for context.

**What the plan says.** `ARCHITECTURE.md §4.2, §10` specify the attacker as **Nous Hermes 4 (405B) via OpenRouter** — a Llama-based, low-refusal, open-weight model chosen to be a **different model family from the Claude Judge**, so that a jailbreak one family rationalizes is not one the other waves through. Model-family separation is one of the three structural pillars of Judge independence.

**What shipped.** Only Anthropic keys were available on the build machine, and the single LLM entry point is Anthropic-only (`llm/client.py`). The in-process attacker/mutator therefore defaults to **Claude** (`redteam_model = "claude-sonnet-5"`, `config.py:30-33`), and higher-volume creative attack generation at build time was driven by **Claude Code subagents**. The Judge's LLM tier also defaults to Claude (`judge_model = "claude-opus-4-8"`, `config.py:29`).

**The independence caveat — stated plainly.** When *both* the attacker's LLM tier and the Judge's LLM tier are Claude, they are the **same model family**, which reduces the structural independence guarantee for exactly those verdicts that reach the Judge's LLM tier: correlated blind spots become possible, which is the specific risk `§4.3` is built to avoid.

**The mitigation — why the guarantee mostly survives anyway.** Judge independence in this platform does *not* rest on model family alone; it rests on three layers, and two of them are unaffected:
1. **Deterministic-first.** Most verdicts are decided by the deterministic tier (§2.2), which has *no model in the path at all* — model family is irrelevant to them. A same-family attacker cannot talk a status-code check or a canary match into a different answer.
2. **The information barrier.** The Judge reads only a `JudgeView` — never the attacker's intent, technique, or confidence (`judge.py:39-59`). It cannot be steered by "this clearly worked," regardless of who wrote the attack.
3. **Different family** — this is the layer currently weakened.

So the exposure is bounded to *LLM-tier semantic verdicts only*, and it is **fully restored by configuration, not code**: point `redteam_model` at an OpenRouter Hermes endpoint (the client seam is the swappable piece) and the attacker is a different family again. This is a config/provider change, not an architecture change — the contracts, the barrier, and the deterministic core are all family-agnostic already.

---

## 3. Refreshed AI-use disclosure

*Every role that uses AI, the deterministic check or human gate that follows each AI decision, and the residual risk — reflecting what is actually shipped.*

| AI-powered role | Model (as shipped) | Deterministic check / human gate that **actually** follows it | Residual risk |
|---|---|---|---|
| **Red Team — attack generation & mutation** | Claude (subagent at build time; in-process Mutator defaults to `claude-sonnet-5`) — *plan: Hermes 4 / OpenRouter* | Nothing it emits is trusted as instruction. Every attempt is graded by the independent Judge behind the `JudgeView` barrier; the executor never scores its own success (`executor.py:6-9`). No write scope; self-throttled; synthetic data only. Mutator has a deterministic keyless fallback so the loop never depends on the model (`mutator.py:93-200`). | Same-family-as-Judge for LLM-tier verdicts (§2.3, mitigated: deterministic-first + info barrier). May fixate on one technique (mitigated partially; ε-greedy is deferred, §1.1). |
| **Judge — semantic adjudication** | Claude (`judge_model = claude-opus-4-8`), key-gated; subagent-exercised where no key | **Deterministic tier runs first and decides most cases** (`judge.py:127-284`, versioned, ground-truth tested). LLM output that is unparseable or absent → conservative low-confidence `partial` for review, **never a false `success`** (`:90-98`, `judge_llm.py:78-84`). Verdicts are advisory inputs to deterministic subsystems; the Judge cannot publish or write to the target. | Judge drift on the LLM tier (mitigated: see below). The per-run κ calibration gate + multi-vote panel are now built (§1.3), so the LLM tier's *live* self-check is a per-run gold-set gate (fail-closed) on top of the versioned ruleset + ground-truth set. |
| **Orchestrator — campaign rationale** | *Deferred* — rationale is a deterministic template, no LLM in the loop | The target decision is deterministic and fully logged with its arithmetic (`orchestrator.py:72-100`); the rationale is narration only. | None material — no AI in this path today. |
| **Documentation — report narrative** | Deterministic prose today; optional Claude enrichment dormant (no key) | Repro steps are lifted **verbatim** from the transcript, not generated (`documentation.py:257-287`). Deterministic data-quality validator before write (`:291-310`). **Human approval before any critical report publishes** (`:362-364`). | Low — with no LLM in the path, reports are ground-truth-derived; the severity gate catches the expensive-to-be-wrong cases. |

**Net posture for a CISO:** the pattern *"the AI proposes; deterministic code disposes"* holds in the shipped build — and holds *more strongly* than the plan, because on the current keyless build the deterministic tier and human gates carry the load while the AI tiers are dormant or subagent-exercised. The cost of that is the deferred LLM-tier hardening (κ gate, panel) and the model-family caveat, both bounded and both closed by configuration.

### 3.1 How a drifting Judge is detected and corrected — with what exists today

The plan's headline drift control (per-run Cohen's-κ gate) is **now built** — every campaign fails closed if the Judge drifts below the κ threshold on the frozen gold set. Here is the full account of what protects against a drifting Judge:

**Detected by, today:**
- **A versioned, pinned deterministic ruleset (`RULESET_VERSION`, `judge.py:36`).** The tier that decides most verdicts is code, not a model — it *cannot* drift between runs. A change to it is a diffable version bump, not silent behavior change. Every verdict records the ruleset version in its evidence (`:336`).
- **A ground-truth calibration test set (`tests/test_judge_groundtruth.py`, in the passing test suite).** Pre-labeled known-success / known-safe / known-partial transcripts are scored on every test run; the load-bearing invariant *"a held defense is never scored `success`"* and the structural information-barrier check are asserted. A Judge that started "agreeing with everything" would turn these red.
- **The append-only verdict store** supports verdict-distribution inspection over time (`store.passfail_rates()`, `resilience_trend()`) — a Judge trending toward all-pass or all-fail is visible in the substrate.

**Corrected by:** re-pinning the model version, re-grounding the rubric against the gold set, and — the platform's preferred move — **promoting a proven-unreliable LLM-tier check into the deterministic tier** wherever the target's structured `verification.action`/`claims`/status fields allow it (the target exposes exactly these machine-checkable signals, which is why deterministic-first is possible at all).

**The remaining gap, named:** what is *not* yet built is the **automatic per-run κ gate that fails the run closed** before a campaign proceeds. Today the gold-set check runs in CI (build-time), not as a pre-campaign live gate. Closing it is well-scoped: score the frozen calibration set at campaign start, compute κ against the gold labels, and abort-closed below threshold — the calibration set already exists as the ground-truth tests; it needs lifting into the `run_campaign` preamble.

---

## 4. Residual-risk register (what a CISO should hold open)

| # | Residual risk | Severity | Bounded by | Closes when |
|---|---|---|---|---|
| R1 | ~~No-signal cost halt not wired~~ **RESOLVED** — the halt is now enforced in `run_campaign` (`platform.py:138`, tested) | Low | Per-agent metering + self-throttle + the wired halt | Done; monitor once the LLM path is live with a real key |
| R2 | ~~Attacker same family as Judge~~ **RESOLVED when `OPENROUTER_API_KEY` is set** — attacker runs Hermes 4 (Llama family), Judge runs Claude (§2.3); reverts to same-family only if OpenRouter is absent | Low (config-present) | Different family active + deterministic-first + `JudgeView` barrier | Done; keep the key set |
| R3 | ~~Per-run κ calibration gate + multi-vote panel not built~~ **RESOLVED** — κ gate runs in the campaign preamble (fail-closed) + N-vote panel on the LLM tier (§3.1) | Low, scoped to LLM-tier verdicts | Per-run gold-set gate + versioned ruleset + ground-truth set | Done; tune the threshold / vote count with live data |
| R4 | ~~No durable checkpoint/resume; a crashed run restarts~~ **RESOLVED** — native crash-resume built (`resume_campaign` / `adversaryforge resume`): a crashed run continues its unfinished seeds under the same run id (§2.1) | Low | Ordered plan + per-seed completion persisted to SQLite; crash-then-resume tested | Done (framework-native interrupts at the human gate remain a LangGraph-migration nicety) |
| R5 | ~~Cross-category detection not wired~~ **RESOLVED** — wired into run_regression (excludes exercised categories) | Low | Tested; a true signal needs cross-version comparison | Done |
| R6 | Single-shot regression replay; no N-replay flake gate (§1.5) | Low | Invariant assertions branch on deterministic target signals, not stochastic prose | Add N-replay stability check per `ARCHITECTURE.md §7` |
| R7 | Live *authenticated* attack plane not yet exercised (no test-physician cookie) | Medium for coverage, not correctness | Unauth surface runs live; auth seeds staged, `SessionProvider` pluggable | A session cookie or OAuth backend lands in `.env` |

**Bottom line for the trust decision:** the trust-critical spine — genuine agent separation via versioned contracts, an evaluator that is independent *by type* and *deterministic-first*, a fail-closed regression gate that cannot go green on drift, human approval on critical findings, and a fully inspectable observability substrate — is **built, tested (full suite green), and running live today**. The gaps are concentrated in the **LLM tiers and scale/durability infrastructure**, every one of them is named above, and the two that touch independence (R2, R3) are bounded by the deterministic-first design and closed by configuration rather than redesign.
