# AdversaryForge — Build Ledger (autonomous loop state)

> **This file is the resumable brain of the overnight autonomous build.** Any session (or context
> reset) can pick up by reading this top-to-bottom. Update it at the end of every cycle. It is the
> source of truth for *what is done, what is next, and what is blocked.* Keep it honest — a green
> checkbox must mean the thing actually works, not that a file exists.

**Started:** 2026-07-21 · **Operator:** Hank (away — autonomous run authorized)
**Deadlines:** MVP Tue 11:59 PM · **Final Fri noon**
**Target (authorized, user-owned):** https://agentforge.hankholcomb.com

## Operating mode (from operator)
- I (lead) build the coherent foundation directly, then **fan out subagents** for independent leaves.
- **Worktrees** where agents would collide; disjoint file paths where they wouldn't (preferred).
- **Autonomous cycles.** After each build cycle, an **auditing swarm pass** adversarially reviews the
  cycle's output before it's accepted. Go as far as possible without the operator; keep debugging
  while tokens remain.

## Blockers / secrets needed for FULL coverage (platform runs without them)
- [ ] **`ANTHROPIC_API_KEY`** not on machine → platform's in-process LLM agents can't call the API.
      **Mitigation:** Judge runs deterministic-only; Red Team mutation + Doc prose driven by Claude
      Code subagents at build time. Drop key in `.env` to unlock in-process LLM agents.
- [ ] **`AGENTFORGE_SESSION_COOKIE`** not available → authenticated attack plane (injection/exfil/
      multi-turn) can't hit the deploy. **Mitigation:** run the *unauthenticated* live surface now;
      authenticated seed campaigns are staged to auto-run when a cookie lands in `.env`.
- No test-physician credential → OAuth automation deferred; `SessionProvider` is pluggable so a
  cookie or future OAuth backend drops in without code changes elsewhere.

## Frozen success gates (the floor — do not descend below)
| # | Gate | Source | State |
|---|------|--------|-------|
| G1 | Deployed target live + submitted URL | Stage 1 / hard gate | ✅ live |
| G2 | `THREAT_MODEL.md` — full surface + ~500-word summary | Stage 2 / hard gate | ✅ built (543-word summary, 6 cats, OWASP) |
| G3 | `evals/` — reproducible cases across ≥3 attack categories | Stage 3 / hard gate | ✅ 23 seeds, 6 cats (8 unauth live + 15 auth staged) |
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

> **Suite: 190+ tests passing** — run `.venv/bin/python -m pytest -q` for the live count. The
> per-cycle `(N total)` figures below are historical snapshots at each cycle's close, not the
> running count.

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
