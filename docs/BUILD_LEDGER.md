# AdversaryForge — Build Ledger (autonomous loop state)

> **Historical record.** This ledger was last updated on 2026-07-24 and is no longer maintained. The
> target deployment it names is offline today; read its "live" and "now" statements as of that date.

> **This file is the resumable brain of the overnight autonomous build.** Any session (or context
> reset) can pick up by reading this top-to-bottom. Update it at the end of every cycle. It is the
> source of truth for *what is done, what is next, and what is blocked.* Keep it honest — a green
> checkbox must mean the thing actually works, not that a file exists.

**Started:** 2026-07-21 · **Operator:** Hank (away — autonomous run authorized)
**Deadlines:** MVP Tue 11:59 PM · **Final Fri noon**
**Target (authorized, user-owned):** `agentforge.hankholcomb.com` (offline today)

## Operating mode (from operator)
- I (lead) build the coherent foundation directly, then **fan out subagents** for independent leaves.
- **Worktrees** where agents would collide; disjoint file paths where they wouldn't (preferred).
- **Autonomous cycles.** After each build cycle, an **auditing swarm pass** adversarially reviews the
  cycle's output before it's accepted. Go as far as possible without the operator; keep debugging
  while tokens remain.

## Blockers / secrets needed for FULL coverage (platform runs without them)
- [ ] **`ANTHROPIC_API_KEY`** not on machine → platform's in-process LLM agents can't call the API.
      **Mitigation:** Judge runs deterministic-only; Red Team mutation + Doc prose driven by Claude
      Code subagents at build time. Drop key in `.env` to unlock in-process LLM agents. *(resolved by 2026-07-24: keyed runs and a verified authenticated run completed; see docs/COST_ANALYSIS.md §1 and reports/DEFENSES_HELD.md)*
- [ ] **`AGENTFORGE_SESSION_COOKIE`** not available → authenticated attack plane (injection/exfil/
      multi-turn) can't hit the deploy. **Mitigation:** run the *unauthenticated* live surface now;
      authenticated seed campaigns are staged to auto-run when a cookie lands in `.env`. *(resolved by 2026-07-24: keyed runs and a verified authenticated run completed; see docs/COST_ANALYSIS.md §1 and reports/DEFENSES_HELD.md)*
- No test-physician credential → OAuth automation deferred; `SessionProvider` is pluggable so a
  cookie or future OAuth backend drops in without code changes elsewhere.

## Frozen success gates (the floor — do not descend below)
| # | Gate | Source | State |
|---|------|--------|-------|
| G1 | Deployed target live + submitted URL | Stage 1 / hard gate | ✅ live |
| G2 | `THREAT_MODEL.md` — full surface + ~500-word summary | Stage 2 / hard gate | ✅ built (543-word summary, 6 cats, OWASP) |
| G3 | `evals/` — reproducible cases across ≥3 attack categories | Stage 3 / hard gate | ✅ 30 seeds, 6 cats (10 unauth + 20 auth); full OWASP Top-10:2021 + LLM Top-10:2025 mapped (see `evals/OWASP_COVERAGE.md`) incl. completion seeds A02/LLM07/LLM08/LLM09 |
| G4 | ≥1 agent role running LIVE against deploy | Stage 3 / hard gate | ✅ full spine ran live |
| G5 | `ARCHITECTURE.md` — multi-agent, ~500-word summary, diagram | Stage 4 / hard gate | ✅ exists |
| G6 | `USERS.md` | Submission | ✅ 4 personas + why-automation |
| G7 | README: setup, arch overview, deployed link, run instructions | Submission | ✅ |
| G8 | ≥3 distinct professional vulnerability reports | Submission | ✅ 3 generated (reproducible, invariant-specific) |
| G9 | AI Cost Analysis (100/1K/10K/100K runs) | Submission | ✅ COST_ANALYSIS.md (grounded in pricing.py; non-linear scale model) |
| G10 | `/contracts` — versioned JSON Schemas, contract tests both sides | Eng req | ✅ 7 schemas, contract tests both sides, byte-deterministic |
| G11 | OWASP Top-10 + LLM-Top-10 mapping on each eval case | Eng req | ✅ every seed mapped |
| G12 | Regression harness: versioned store, replay, reappearance detect | Platform req | ✅ fixed + fail-closed; `regress` runs live |
| G13 | Observability: coverage/passfail/trend/cost/open-findings queries | Platform req | ✅ store + `status` |
| G14 | Multi-agent system actually runs a campaign end-to-end | Platform req | ✅ campaign+regress+report all run live |

## Component board
> **Note:** this board is the *initial Cycle-0 plan* and is intentionally left as a historical
> snapshot. For current state, the **Frozen success gates** table above and the **Cycle log** below are
> authoritative — every component listed here is now built, tested (the full passing suite), and running live.

Legend: ⬜ todo · 🔨 doing · 🧪 built-untested · ✅ done+verified · 🚫 blocked · 🔍 in-audit

| Component | Path | State | Notes |
|-----------|------|-------|-------|
| Project scaffold + venv | `pyproject.toml`, `.venv` | 🔨 | |
| Config / settings | `adversaryforge/config.py` | ⬜ | reads `.env` |
| Target adapter + endpoint map | `adversaryforge/target/adapter.py` | ⬜ | pinned OpenAPI-driven |
| SessionProvider (cookie/anon/oauth) | `adversaryforge/target/session.py` | ⬜ | pluggable |
| Throttled HTTP client | `adversaryforge/target/client.py` | ⬜ | self-throttle, corr-id |
| Inter-agent contracts (pydantic) | `adversaryforge/contracts/` | ⬜ | mirror `/contracts` schemas |
| `/contracts` JSON Schemas (versioned) | `contracts/` | ⬜ | G10 |
| Observability store (SQLite) | `adversaryforge/observability/store.py` | ⬜ | G13 |
| Deterministic Judge core | `adversaryforge/agents/judge.py` | ⬜ | verification-block parser |
| Red Team agent | `adversaryforge/agents/redteam.py` | ⬜ | seed exec + LLM mutate |
| Orchestrator (deterministic scoring) | `adversaryforge/agents/orchestrator.py` | ⬜ | |
| Documentation agent | `adversaryforge/agents/documentation.py` | ⬜ | G8 |
| Regression harness | `adversaryforge/harness/regression.py` | ⬜ | G12 |
| Seed attack suites (≥3 cat) | `evals/seeds/` | ⬜ | G3, G11 |
| CLI entrypoint | `adversaryforge/cli.py` | ⬜ | run campaign/regression/report |
| THREAT_MODEL.md | `THREAT_MODEL.md` | ⬜ | G2 |
| USERS.md | `USERS.md` | ⬜ | G6 |
| README.md | `README.md` | ⬜ | G7 |
| Cost analysis | `docs/COST_ANALYSIS.md` | ⬜ | G9 |

## Cycle log

> **Suite: 241 tests passing on 2026-07-24** — run `.venv/bin/python -m pytest -q` for the live count. The
> per-cycle `(N total)` figures below are historical snapshots at each cycle's close, not the
> running count.

### Cycle 8 — audit-fix loop 3/3 (Fable lead + 3 auditors: completeness / fresh-clone-repro / doc-honesty) ✅ DONE
- Completeness critic: submission **complete & defensible, no fatal/missing deliverable** (all p13 artifacts,
  7 capabilities, full suite green, live target up, fresh-clone reproducible). Surfaced the valued NEGATIVE
  result in `reports/` (new `reports/DEFENSES_HELD.md`): the 4 LLM-plane categories (injection/state/tool/
  identity) held with **zero exploits** live; every committed finding is infra-level. Added honest as-built
  caveats inline in ARCHITECTURE §6 (default sweep runs all seeds; scorer uses a 4-signal subset) and §7
  (regression replay is invoked, not auto-fired on a version delta).
- Fresh-clone repro: verified clean on the uv path (bootstrap, byte-for-byte reports, 30 seeds/OWASP,
  regress fail-closed exit 1, deployed link 200). Fixed the pip fallback to probe for Python 3.11+ and fail
  loudly (was silently grabbing an old python3); clarified the `trace` no-spans message; `status` always
  shows the cost-scaling-rate line now (n/a keyless).
- Doc-honesty sweep: docs accurate except AS_BUILT "ten→eleven invariant rules" (+HSTS in the enumeration,
  widened cite). Full suite + ruff green, bootstrap syntax OK.

### Cycle 7 — audit-fix loop 2/3 (Fable lead + 3 auditors: platform-security / robustness / testing-the-tester) ✅ DONE
- Testing-the-tester (highest value): the κ drift gate covered only 7/12 invariants and was **blind to
  injection drift** (sabotaging `_judge_injection` kept κ=1.0). Expanded the gold set to all **11 rule-backed
  invariants (22 cases)** and implemented the documented **"2+ flips fail"** rule, so a single-rule break now
  fails closed regardless of gold-set size. Removed the orphaned `INV-NO-INVENTION` (fake coverage → folded
  into WITHHOLD-UNGROUNDED). Added an A09 verbose-error branch to `_judge_info_disclosure` so the
  error-oracle seed yields a real signal (was always `partial`).
- Robustness: **hard per-campaign spend ceiling** (`max_campaign_usd`, halts regardless of signal — the
  no-signal governor left a productive-then-runaway run uncapped); wrapped the per-seed loop so one seed's
  bug is logged + skipped, not fatal (+ test); crash-resume now models a real interrupt (BaseException);
  SQLite `busy_timeout` → 30s.
- Platform self-security: confirmed SAFE (no blast-radius/cookie/path-traversal/key escape). Hardened the
  **LLM adjudicator prompt** against target→evaluator injection (fenced untrusted transcript + inert-data
  instruction); escaped report code-fences; deduped the keyless mutator against the base.
- Full suite **241**, ruff clean, live κ=1.0. Registry now **11 invariants** (added transport, removed the
  orphaned no-invention).

### Cycle 6 — audit-fix loop 1/3 (Fable lead + 3 auditors: correctness / spec / doc-honesty) ✅ DONE
- Correctness: no critical/high bugs. 5 low fixes — hardened `_judge_transport` (401/403 + non-200 →
  inconclusive `error`, HSTS finding only on a served 200); wired the schema-v4 `finding_count` column
  (`record_exploit` increments, `resilience_trend` reads it); tightened cross-version `being_fixed` to compare
  success RATES at comparable volume (kills a fewer-attempts false-fire); added a `denial_of_service`
  byte-repro test that exercises the preserve-latency branch.
- Spec: surfaced `cost_rate()` in `status` — closes observability Q5's "rate" half from the CLI snapshot.
- Honesty: fixed the ATO packet (κ gate DEFERRED→**built & live**; §6 self-scan deferred→**run**) + AS_BUILT
  κ self-contradiction; reworded ARCHITECTURE §12 (no queue ships — semaphore + sequential await, queue = N/A
  scale-time); refreshed stale counts (STAGE2 11→12 invariants, COST_ANALYSIS 27→30 seeds) + drift-proofed
  AS_BUILT store cites to symbols (SCHEMA_VERSION 3→4). Full suite 240, ruff clean.

### Cycle 5 — final gap-audit + fix swarm (Fable lead + 6 build agents + adversarial verify) ✅ DONE
- Full spec-conformance audit (6 read-only verifiers) against the extracted PDF, then a disjoint-path
  build swarm. **OWASP coverage completed to 10/10 web (2021) + 10/10 LLM (2025)** — new seeds
  `crypto-hsts-missing` (A02, new `INV-TRANSPORT-SECURITY` Judge rule + HSTS check, response-headers now
  persisted to the transcript), `llm08-vector-cross-context-recall` (LLM08), `llm09-misinformation-…`
  (LLM09); `pi-direct-system-prompt-reveal` dual-tagged LLM07; `OwaspLlm` enum + schemas re-exported
  (CHANGELOG amended). Reviewer map at **`evals/OWASP_COVERAGE.md`**. Every seed now carries an
  `exploitability` rating (Stage-3 gap closed).
- Fixes (each reproduced → fixed → sabotage-proved): DoS vuln reports no longer redact their own latency
  (`documentation.py` category-scoped normalization → real digits `9321ms > 8000ms`); **real DB schema
  migration** (v3→v4 ALTER+backfill, `store.py`) replacing the no-op; **cross-VERSION** regression flag
  (was a live no-op) + regression auth-threading + real replay-scan SLO (`regression.py`); genuine
  two-sided producer→consumer contract test (`tests/test_contract_integration.py`); burn-rate query
  `cost_rate()`; redteam token cost metering; perf baseline records LLM-call latency + full regression.
- **ATO §6 self-scan run for real**: `pip-audit` clean, `bandit` 4 Low/0 Med/0 High (all accepted).
- Verified LIVE post-change: `campaign` (run_8e11ba3b4c77, authenticated, κ=1.0), the new A02 transport
  case fires live (INV-TRANSPORT-SECURITY → success), `regress` fail-closed, cost/observability populate. Full suite
  **236 passed**. Peer-integration exercise confirmed OPTIONAL (operator) → out of scope.

### Cycle 4 — fine-grained execution tracing (lead) ✅ DONE
- Built a contextvar-linked span tracer (`observability/tracing.py`) + a `spans` table (schema v3,
  auto-migrates) recording nested spans *inside* each agent, with timing + attributes:
  `orchestrator.run_seed` → `target.request` (method/path/status/latency) → `judge.evaluate` →
  **`judge.rule`** (which invariant rule fired, the signals it read, its sub-verdict + rationale);
  plus `redteam.mutate`/`redteam.variant` on the mutation path and `llm.call` spans (model/tokens/USD/
  response preview) that populate when an API key is present.
- Non-invasive (tracer in a ContextVar → deep code calls `trace()` with no signature changes),
  zero-cost when off (`ADVERSARYFORGE_TRACE`, default on), async-safe, never breaks a run.
- Bound in campaign + regression; `adversaryforge trace [run_id]` renders the span tree. +4 test cases.
- Verified live: a campaign emits ~32 spans across 3 agents with real per-rule Judge timing.

### Cycle 3 — cost analysis, perf baseline, as-built reconciliation (3 builders) ✅ DONE
- Workflow `wf_fcf53241`: COST_ANALYSIS.md (G9), a load/baseline perf harness + PERFORMANCE_BASELINE.md,
  and AS_BUILT.md — each pipelined into an audit + integration critic. 7 agents, 0 errors.
- **perf-baseline: full PASS** — real numbers: 100 attacks / 55.4s / 1.8 per sec against the live target,
  throttled-network bottleneck identified, peak 9 MB traced / 68 MB RSS; **baseline DB verified
  byte-for-byte untouched** (perf run isolated to a temp dir). Also wrote `docs/DEMO_SCRIPT.md` (lead).
- **Audit caught 2 honesty defects → fixed the RIGHT way:**
  - COST_ANALYSIS §5 claimed the no-signal cost halt was enforced, but it wasn't wired. **Fixed by
    actually wiring it**: `should_halt_no_signal()` (pure, tested) called per-seed in `run_campaign`;
    halts + logs `cost_halt` + returns `halted_no_signal` when budget is spent with zero signal. This
    satisfies the case-study "halt when cost accrues without producing signal" requirement. Updated
    COST_ANALYSIS §5 + AS_BUILT (Cost Governor now ✅) to match. +4 test cases.
  - AS_BUILT "verify" block used the console script, which was broken in the over-installed venv →
    switched the doc to the cwd-robust `python -m adversaryforge.cli` form.
- **Editable-install root cause (final):** hatchling's `.pth` lacks a trailing newline AND repeated/
  concurrent `uv` installs leave conflicting `.pth` files → `site` stops adding repo-root to sys.path.
  A single clean `uv pip install -e '.[dev]'` works (verified: REPO on path=True, console OK). README
  notes the `-m` fallback. **Rule stands: no concurrent/repeat installs.**

### Cycle 2 — wire the mutation loop (lead) ✅ DONE
- Wired the **mutation loop** into the Orchestrator/campaign: a `partial` verdict on a message-bearing
  seed now autonomously generates N variants (the Mutator; deterministic keyless fallback), executes
  each as a child attempt (generation+1, parent linked), re-judges, and promotes any breakthrough —
  the case study's "take a partial → generate 10 variants" behavior. `mutation_breakthrough` events
  land on the timeline. +2 offline tests (78 total pass). CLI shows `partials mutated`.
- **Editable-install root cause found & fixed:** the `adversaryforge` console script kept breaking
  because concurrent `uv pip install` during the Cycle-1 fan-out created a duplicate
  `_editable_impl_adversaryforge 2.pth` that broke the finder. A single clean
  `uv pip install -e '.[dev]'` works (verified console script + `-m`). **Rule for future cycles:
  builders must NOT run installs** — the editable package already picks up new files.
- Verified live: campaign (3 findings, mutation loop active), regress, report all run via console script.

### Cycle 1 — parallel fan-out + audit swarm (7 builders) ✅ DONE
- Workflow `wf_91df4b1a`: 7 builders (disjoint paths) → per-component adversarial 4-lens audit →
  integration critic. 15 agents, 0 errors, ~1.1M tokens.
- **Delivered:** regression harness (G12), documentation agent + 3 reports (G8), 15 authenticated
  seeds all-6-categories (G3/G11), `/contracts` 7 JSON schemas + 29 contract tests (G10), LLM layer
  (adjudicator+mutator+pricing, key-gated), THREAT_MODEL.md (G2), USERS.md (G6). Plus README (G7, lead).
- **Audit caught real defects (green tests were hiding them):**
  - harness FAIL — returned `cases`, but CLI+spec need `details`/`passed`/`note` → `regress` crashed;
    also a dead target scored every case "passed". **Fixed**: added `details` contract, made `error`
    outcome *inconclusive* (fail-closed gate = `failed==0 and errored==0`), corrected the test that
    encoded the bug, added a CLI-contract regression test.
  - auth-seeds HIGH — `pi-indirect-document-injection` relied on a `from-upload` substitution that
    didn't exist + sent JSON to a multipart endpoint. **Fixed**: implemented real multipart upload +
    document-id capture + sentinel substitution in the executor (+3 offline tests); seed now honest.
  - editable install got clobbered by a builder → `adversaryforge` console script broke. **Fixed** by
    reinstall. Also cleaned test-fixture pollution from the real SQLite DB (regenerated clean baseline).
- **Verified live:** clean campaign (3 findings), `regress` (3 open findings, gate NOT GREEN, correct),
  `report` (3 professional reports). **full suite green.**
- Minor polish deferred (doc markdown lists, canary false-positive hardening, threat-model nits) → Cycle 2.

### Cycle 0 — foundation (lead) ✅ DONE
- Built the coherent spine: config, target adapter (24 eps, 11 invariants), pluggable
  SessionProvider, throttled client, versioned contracts, SQLite observability store,
  deterministic Judge (11 invariant rules), Red Team seed executor, deterministic
  Orchestrator, CLI, 8 unauthenticated seeds (3 categories).
- **Ran LIVE** (`adversaryforge campaign`) vs the deploy: 8 attempts → 3 defenses held
  (401 authz), 3 confirmed findings (dependency enumeration `/ready`, full OpenAPI
  exposure, absent rate limiting), 2 flagged-for-review. Cleared **G4**.
- 17/17 Judge ground-truth tests pass (incl. "held defense never == success" invariant
  + info-barrier structural check).
- Verified findings are honest: fixed the observations seed (422-before-auth meant it
  wasn't reaching the auth check).

### Cycle 1 — parallel fan-out (next)
Plan: fan out subagents on disjoint paths, then an audit swarm. Targets:
1. Authenticated seed suite (all 6 categories) — G3/G11.  2. Regression harness — G12.
3. Documentation agent + 3 vuln reports — G8.  4. THREAT_MODEL.md — G2.
5. `/contracts` JSON Schemas + contract tests — G10.  6. LLM adjudicator + mutator (key-gated).
7. USERS.md, README.md, COST_ANALYSIS.md — G6/G7/G9.

## Autonomous-loop protocol (how each cycle runs)
1. **Plan** the cycle: pick the next 2–5 board items with the highest gate-leverage.
2. **Fan out** builder subagents on disjoint paths (worktrees only on collision).
3. **Integrate**: merge, `uv run pytest -q`, fix breakages.
4. **Audit swarm**: spawn adversarial reviewers (correctness / spec-conformance / does-it-actually-run
   / security-of-the-platform-itself). Only ✅ an item that survives audit.
5. **Update this ledger** (board + cycle log + gates). Commit.
6. Repeat until gates met or tokens low; then keep debugging the weakest ✅→🧪 items.
