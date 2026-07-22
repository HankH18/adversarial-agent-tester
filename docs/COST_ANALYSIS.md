# AI Cost Analysis — AdversaryForge

*Actual development spend, and projected production cost of running the adversarial
platform at 100 / 1K / 10K / 100K test runs, with the architectural changes each
scale requires. This is deliberately **not** `cost-per-token × n` — the LLM calls in
this platform are **conditional**, so the per-run cost is governed by invocation
*rates*, and the right architecture bends the curve sub-linearly as volume grows.*

All USD rates below are the real per-model rates from
[`adversaryforge/llm/pricing.py`](../adversaryforge/llm/pricing.py) (USD per 1M
tokens, standard/non-introductory, so the cost governor never under-counts):

| Model (role) | Input $/Mtok | Output $/Mtok |
| --- | --- | --- |
| `claude-opus-4-8` — Judge adjudicator (`judge_model`) | 5.00 | 25.00 |
| `claude-sonnet-5` — Red Team mutator & Doc enrichment (`redteam_model`, `doc_model`) | 3.00 | 15.00 |
| `claude-haiku-4-5` — cheaper high-volume mutation (10K+) | 1.00 | 5.00 |

---

## 1. Actual development spend

**Keyless in-process LLM spend: `$0.00`. Keyed spend: a few tenths of a cent per campaign.**

Two honest figures, both from the platform's own per-agent cost meter (not estimates):

- **Keyless** — the bulk of the build ran with **no `ANTHROPIC_API_KEY`** (`settings.has_llm == False`);
  the deterministic Judge + subagent-driven roles produced every finding, and the cost store returns
  exactly zero (below).
- **Keyed** — once an `ANTHROPIC_API_KEY` (and later an `OPENROUTER_API_KEY`) were added, a live
  campaign meters real spend: e.g. **one Claude-Opus Judge adjudication ≈ `$0.0047`** on the
  unauthenticated surface (the only LLM call an unauth run makes). The Hermes attacker adds spend only
  when the mutator fires (chat partials); OpenRouter reports the true `usage.cost` per call.

The keyless zero, reproduced:

```
$ python -c "from adversaryforge.observability.store import Store; \
             from adversaryforge.config import get_settings as g; \
             print(Store(g().db_path).cost_summary())"
{'usd': 0, 'input_tokens': 0, 'output_tokens': 0, 'llm_calls': 0}
```

How the current findings were produced without spending anything through the platform:

- **The Judge ran fully deterministic.** `Judge.evaluate()` is deterministic-first
  (`agents/judge.py`): a per-invariant rule dispatch (`INV-AUTHZ-PATIENT`,
  `INV-RATE-LIMIT`, `INV-INFO-DISCLOSURE`, …) resolves the verdict from the target's
  actual HTTP status and response body. The LLM adjudicator is only *injected* when a
  key is present, and with no key it is `None`, so every verdict this build came from
  the rule engine — zero tokens.
- **The live surface was the unauthenticated target.** Real evidence was gathered by
  hitting `https://agentforge.hankholcomb.com` directly; no LLM sits between the
  executor and the target.
- **The LLM *roles* were driven by Claude Code subagents at build time.** Mutation
  strategy, report prose, and orchestration reasoning were exercised by the build
  harness (this agent), **not** billed through the platform's Anthropic meter. That
  spend belongs to the development tooling, not to a production campaign.

**What a keyed run would meter.** The moment `ANTHROPIC_API_KEY` is set, every call is
metered at the agent level via `store.log_cost(run_id, agent, model, in, out, usd)`
and surfaced by `store.cost_summary()`. Using the grounded per-call costs in §2, a
single **full 23-seed authenticated sweep** would meter roughly **$0.05–$0.30**,
depending on how many attempts escalate to the LLM Judge and how many partials trigger
mutation. A keyless sweep stays at **$0.00** and still produces verdicts and reports.

---

## 2. The token-per-attack model (grounded in the real prompts)

A "test run" here is **one primary attack attempt**: one seed executed against the
target, judged, plus any mutation *that attempt* triggers. The platform makes an LLM
call only in three conditional situations — this is the whole reason the cost is not
linear in token-count:

| Role | When it fires | Model | Calls |
| --- | --- | --- | --- |
| **Judge adjudicator** (`llm/judge_llm.py`) | Only when the deterministic rule engine returns `None` (semantically-ambiguous: e.g. `200` + withheld answer, or an un-dispatched invariant). `Judge.evaluate()` calls the LLM *only* on that fall-through. | Opus-4-8 | 1 per ambiguous attempt |
| **Red Team mutator** (`llm/mutator.py`) | Only on a `partial` verdict **and** a message-bearing seed (`Orchestrator._mutate_and_run`). Produces **all N variants in a single call** (`max_tokens=2048`), not N calls. | Sonnet-5 | 1 per mutated partial |
| **Documentation enrichment** (`agents/documentation.py`) | Optional prose-sharpening pass, once per **confirmed** exploit. Currently a no-op hook (no `enrich_report` is wired), so today it is $0; modeled here as the production-enabled case. | Sonnet-5 | ≤1 per confirmed exploit |

Target selection, rationale templating, report *structure*, reproduction steps,
promotion, and dedup are all **deterministic** — no tokens.

**Per-call token counts** (system-prompt sizes measured directly; user/output sized
from the real templates):

| Call | Input tok | Output tok | Cost (low → high) |
| --- | --- | --- | --- |
| Judge adjudicator (sys ≈271 tok + transcript view; JSON verdict, `max_tokens=512`) | 500 → 900 | 100 → 200 | **$0.005 → $0.010** |
| Mutator (sys ≈213 tok + partial + feedback; N-variant JSON, `max_tokens=2048`) | 500 → 700 | 1,200 → 1,800 | **$0.020 → $0.030** |
| Doc enrichment (report + exploit → sharpened summary/impact) | ~1,500 | ~800 | **$0.017** |

**Per-run expected cost**, combining the invocation rates with the per-call costs:

- `a` = adjudication rate (share of attempts the deterministic Judge can't resolve).
  Low **0.05**, High **0.30**.
- `p` = partial-and-mutatable rate (share triggering an N-variant mutation).
  Low **0.05**, High **0.20**.
- `N` = variants per mutation = **8** (`n_variants` default).
- `s` = confirmed-exploit rate (→ doc report). High-scenario doc enrichment on at **0.10**.

| Cost line | Low (deterministic-heavy) | High (LLM-heavy) |
| --- | --- | --- |
| Judge adjudication `a · $adj` | 0.05 · $0.005 = $0.00025 | 0.30 · $0.010 = $0.00300 |
| Mutation `p · $mut` | 0.05 · $0.020 = $0.00100 | 0.20 · $0.030 = $0.00600 |
| Mutation-child adjudication `p · N · a · $adj` | 0.02 · $0.005 = $0.00010 | 0.48 · $0.010 = $0.00480 |
| Doc enrichment `s · $doc` | 0 (deterministic) | 0.10 · $0.017 = $0.00170 |
| **Per-run total** | **≈ $0.0015** | **≈ $0.016** |

The ~10× band between the two columns is entirely the invocation rates — the same
tokens, invoked more or less often. That is the lever architecture pulls on.

---

## 3. Projected production cost by scale

Naive linear projection of the §2 per-run costs (the pre-architecture upper/lower band):

| Test runs | Low @ $0.0015/run | High @ $0.016/run |
| --- | --- | --- |
| **100** | $0.15 | $1.60 |
| **1,000** | $1.50 | $16 |
| **10,000** | $15 | $160 |
| **100,000** | $150 | $1,600 |

The High column is what you pay if you scale the 100-run behavior **unchanged**. The
point of §4 is that you don't: each scale introduces an architectural change that
lowers the *effective* per-run rate, so the real 100K cost sits well below the naive
$1,600, and the deterministic-heavy path can hold a large fraction of runs at ~$0.

Note also a **non-token** amplification the token model hides: every mutation fires
**N = 8 additional HTTP requests at the target**. At 100K runs with a high partial
rate that is hundreds of thousands of extra target hits — an availability and
denial-of-wallet concern for the *target*, which is why the self-throttle in §4 is a
cost control, not just politeness.

---

## 4. Architectural changes per scale (not linear × n)

### 100 runs — laptop, hosted API, no new infrastructure
Runs as-is. In-process `run_campaign` for-loop, `Store` on SQLite, the built-in
self-throttle (`max_concurrency=2`, `min_request_gap_s=0.5`) against a target with no
inbound rate limiting. Deterministic-Judge-first already keeps most of these runs at
**$0**; hosted Opus/Sonnet on the conditional minority is trivially affordable
($0.15–$1.60 total). No caching needed — the working set is tiny.

### 1,000 runs — cache & dedup to suppress redundant LLM calls
The cost driver at this scale is *repeat* LLM work, not volume.
- **Mutation-result caching.** Memoize `Mutator.mutate()` output keyed by
  `(base_messages, target_invariant, judge_feedback)`. Re-running a campaign or
  re-hitting the same partial then reuses variants instead of paying the ~$0.02–$0.03
  Sonnet call again — the single most expensive per-call line.
- **Exploit dedup** already exists: `Store.record_exploit()` returns `inserted=False`
  on a duplicate and the orchestrator logs a `dedupe` event — no second report, no
  second doc call for a known finding.
- **Deterministic-Judge-first** is already the design (`Judge.evaluate()` only calls
  the LLM on a `None` fall-through). At 1K runs the win is operational: keep the
  ambiguous rate `a` low by widening the rule dispatch so fewer attempts escalate to
  the $5/$25 Opus adjudicator.

### 10,000 runs — batch, cheaper mutation model, a work queue, throttle vs. rate limits
Volume now collides with provider limits and Opus cost.
- **Batch the mutator / cheaper model.** The mutator already emits all N variants in
  one call; at 10K, swap `redteam_model` from `claude-sonnet-5` ($3/$15) to
  `claude-haiku-4-5` ($1/$5) for high-volume mutation — a ~3× cut on the dominant LLM
  line, configurable with no code change (`ADVERSARYFORGE_REDTEAM_MODEL`).
- **Work queue.** Replace the in-process `for seed in runnable` loop in
  `run_campaign` with a durable queue so attempts (and the N mutation children each
  partial fans out) are worked by a pool, survive restarts, and back-pressure cleanly.
- **Self-throttle vs. provider rate limits.** `max_concurrency` and
  `min_request_gap_s` currently exist to protect the *target*; at 10K they must also
  respect Anthropic RPM/TPM. The knob that stops us DoS-ing the clinical target is the
  same knob that keeps us under the API rate ceiling — tune both together.

### 100,000 runs — self-host the attacker, scale storage, shard, spot compute
At six figures the per-token API bill for mutation dominates, and SQLite is the
bottleneck.
- **Self-host the attacker model.** Point `redteam_model` at a locally-hosted open
  model. Mutation is the highest-frequency LLM call (fires on every partial and is the
  costliest per-call at Sonnet rates); moving it off the metered API removes that
  entire line from the marginal cost — this is where the naive $1,600 collapses.
  Keep the **Judge on hosted Opus** — adjudication is lower-frequency and independence/
  quality of the evaluator is worth more than its cost.
- **DB / storage scaling.** Migrate `Store` from SQLite to Postgres and index the hot
  paths (`attempts`, `verdicts`, `exploits`, `cost_ledger`) so `coverage_by_category()`,
  `passfail_rates()`, and `cost_summary()` stay cheap as the tables grow to millions
  of rows.
- **Sharded campaigns + spot compute.** Partition the seed × patient-id space across
  workers and run the fleet on interruptible spot instances — the workload is
  embarrassingly parallel and fully restartable (durable queue + Postgres), so spot
  reclaims cost nothing but a re-queue.

The through-line: cost does not scale `× n` because (a) most runs never call an LLM at
all, (b) caching/dedup remove *repeat* calls, and (c) the biggest LLM line (mutation)
is moved to a cheaper model and then off-API entirely as volume justifies it.

---

## 5. Cost as a first-class signal

Cost is metered and budgeted, not observed after the fact:

- **Per-agent metering.** `Store.log_cost(run_id, agent, model, input_tok, output_tok,
  usd)` records spend tagged by *agent* (`redteam`, `judge`, `documentation`), so
  `cost_summary()` answers "how much did the Red Team spend vs. the Judge," not just a
  platform total. Every mutation logs its cost via
  `Orchestrator._mutate_and_run → store.log_cost(...)`.
- **A no-signal halt — enforced in the loop.** `settings.nosignal_halt_usd` (default
  **$2.00**, `ADVERSARYFORGE_NOSIGNAL_HALT_USD`) is the governor's budget knob, and it
  is now **actively enforced**: after every seed, `run_campaign` reads the live per-run
  cost (`cost_summary(run_id)`) and the live confirmed-exploit count, and calls
  `should_halt_no_signal(spent, budget, confirmed)` — a pure, unit-tested decision
  (`tests/test_cost_governor.py`). When spend reaches the budget with **zero** confirmed
  exploits, the campaign **breaks out of the loop**, logs a `cost_halt` event, and
  returns `halted_no_signal=True`. So the governor decides on *cost-per-signal*, not raw
  spend: a campaign burning budget on a saturated, all-defended category stops itself
  instead of grinding tokens for no new findings. Set the budget to `0` to disable.

This is the CISO-grade answer to "how much did this run cost, and at what rate is cost
scaling": the platform meters per agent and per run, **and stops on its own** before the
bill outruns the security signal. (On this keyless build spend is ~$0, so the wall has
nothing to stop yet — but the control is live, not aspirational.)
