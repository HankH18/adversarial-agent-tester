# AdversaryForge

**A red-team platform that attacks an AI clinical chatbot, judges each attempt, and writes reproducible vulnerability reports.** The target was the author's own [Clinical Co-Pilot for OpenEMR](https://github.com/HankH18/openemr-base-clean), deployed with synthetic data only (authorized; never real PHI). That deployment ran at `agentforge.hankholcomb.com` and is offline today.

> The goal is not to find one jailbreak. It is a system that can tell — run after run, version after
> version — whether a *category* of exploit is still open, whether a fix actually held, and whether
> closing one hole opened another. Built to the standard of *a hospital CISO deciding whether to
> trust it with continuous testing of systems their physicians depend on.*

- **Results against the deployment (2026-07-21 to 07-24):** 30 OWASP-mapped attack seeds (10 unauthenticated, 20 authenticated); 5 published findings, all on the anonymous surface: 2 medium denial-of-service and 3 low information-disclosure. Each has a report in [`reports/`](reports/) and a verbatim transcript in [`evals/published_findings.yaml`](evals/published_findings.yaml). A sixth confirmed finding, a low missing-HSTS header, has no report; it and the authenticated attacks that held are recorded in [`reports/DEFENSES_HELD.md`](reports/DEFENSES_HELD.md).
- **Throughput:** 100 attack executions in 60.0 s; target HTTP p95 1,810 ms; judge overhead p50 0.37 ms ([`docs/PERFORMANCE_BASELINE.md`](docs/PERFORMANCE_BASELINE.md)).
- **How verdicts are made:** a deterministic rule engine decides first; a Claude judge from a different model family than the attacker is a key-gated fallback. All five published findings were decided by the rule engine.
- **Run it locally, offline, no keys:** after the Quickstart install, `python -m adversaryforge.cli seed-published` then `python -m adversaryforge.cli report` regenerates the five `VULN-*.md` reports from the committed ledger.
- **Stack:** Python 3.11, httpx, pydantic v2, JSON Schema contracts, Typer, SQLite, Anthropic SDK, OpenRouter, pytest, GitHub Actions.
- **Docs:** [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`docs/AS_BUILT.md`](docs/AS_BUILT.md) (plan vs shipped) · [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md) · [`docs/BUILD_LEDGER.md`](docs/BUILD_LEDGER.md) (historical)

---

## What it is (agent roster)

Four AI agent roles + two deterministic subsystems, coordinated by a deterministic Python orchestrator (LangGraph is the planned migration — see AS_BUILT). Agents
never call each other directly — they exchange **versioned, typed JSON-Schema contracts**
([`/contracts`](contracts/)).

| Component | Role | Trust | Powered by |
|---|---|---|---|
| **Orchestrator** | Strategist — deterministic target selection from the observability substrate | trusted | code (deterministic rationale; LLM narration deferred) |
| **Red Team** | Adversary — seed execution + mutation of partial attacks | untrusted / sandboxed | **Hermes 4 405B via OpenRouter** (Meta-Llama family) when `OPENROUTER_API_KEY` is set; Claude fallback |
| **Judge** | Independent evaluator — success/failure/partial per attempt | semi-trusted, cannot act | **deterministic-first**, LLM-second on **Claude** — a *different model family* from the Hermes attacker |
| **Documentation** | Scribe — confirmed exploit → professional vuln report | gated | Claude + human approval on criticals |
| **Regression Harness** | Freezes exploits into replayable, versioned tests | deterministic | code |
| **Observability** | Append-only substrate the Orchestrator reads | deterministic | SQLite |

Three decisions carry the design: **(1)** Judge independence is *structural* — it sees only a
`JudgeView` (transcript + invariant + expected-safe), never the attacker's intent. **(2)**
Deterministic by default; AI only where generation or semantic judgment is irreducible. **(3)**
Autonomy is bounded by blast radius — read-mostly against the target, write-only against our own
store, human gate before publishing a critical finding.

---

## Quick start

Requires **Python 3.11+** and [`uv`](https://github.com/astral-sh/uv).

Run the CLI as **`python -m adversaryforge.cli <cmd>` from the repo root** — this always works. (The
`adversaryforge` console script is equivalent but, on macOS, `uv` marks the editable-install `.pth`
hidden, which Python's `site` skips; if the console script reports `No module named 'adversaryforge'`,
run `chflags nohidden .venv/lib/python*/site-packages/*.pth` once, or just use the `-m` form.)

**Fastest path — offline, zero secrets** (installs, then proves the CLI end-to-end):

```bash
./scripts/bootstrap.sh
```

Or step by step:

```bash
# 1. Set up the environment (uv — or the plain-pip fallback just below)
uv venv                    # uv provisions a Python that satisfies requires-python (>=3.11)
uv pip install -e '.[dev]'
#    No uv?  python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# 2. Configure (all secrets are OPTIONAL — the platform runs without them)
cp .env.example .env      # then edit — see "Authentication & keys" below

# 3. START HERE (fully offline, no target, no secrets). The SQLite store is git-ignored and
#    starts EMPTY, so status/report show nothing until something populates it:
.venv/bin/python -m adversaryforge.cli seed-published  # load the REAL committed findings; report regenerates VULN-*.md byte-for-byte
.venv/bin/python -m adversaryforge.cli seed-demo       # OR: quick illustrative findings (mode='demo', excluded from reports)
.venv/bin/python -m adversaryforge.cli status          # observability snapshot the Orchestrator reads
.venv/bin/python -m adversaryforge.cli report          # (re)generate reports/*.md from the loaded findings

# 4. LIVE (needs the authorized target, which is offline today; the authenticated plane also needs a session cookie)
.venv/bin/python -m adversaryforge.cli campaign   # attack the target
.venv/bin/python -m adversaryforge.cli resume     # resume a crashed/interrupted campaign
.venv/bin/python -m adversaryforge.cli regress    # re-run the fail-closed regression suite
```

### CLI

Invoke as `python -m adversaryforge.cli <command>` from the repo root (or `adversaryforge <command>`
after a clean install — see the note above).

| Command | What it does |
|---|---|
| `campaign` | Orchestrator selects → Red Team executes → Judge evaluates → exploits stored |
| `status` | Coverage per category, pass/fail rates, resilience trend, open findings, cost |
| `seeds` | List the seed library with test-design roles (boundary/invariant/regression) |
| `seed-published` | Load the committed findings ledger (real exploits behind `reports/`) so a fresh clone regenerates the reports + runs status/regress. See [`docs/REMEDIATION.md`](docs/REMEDIATION.md) |
| `regress` | Re-run confirmed exploits; exits non-zero unless the fail-closed gate is GREEN. **On the shipped/demo data this is correctly RED** — the target was still rate-limit-vulnerable when last tested (2026-07-24), so the gate refused to go green; with that deployment offline today, the replays come back `errored` (inconclusive), which also keeps it red. That is the harness working, not a platform failure. |
| `report` | (Re)generate professional vulnerability reports |
| `trace [run_id]` | Render the fine-grained per-agent execution trace (span tree) for a run |

---

## Authentication & keys

The platform is designed to run and produce **real evidence without any secrets**, then unlock more
coverage as secrets are provided.

| Secret (`.env`) | Unlocks | Without it |
|---|---|---|
| `AGENTFORGE_SESSION_COOKIE` | The **authenticated** attack plane (prompt injection, PHI exfil, multi-turn) against the deployed target (offline today) | Runs the **unauthenticated** surface (info disclosure, error-oracle, rate-limit, auth enforcement) |
| `ANTHROPIC_API_KEY` | The platform's **in-process** LLM Red Team mutator + LLM-second Judge + Documentation prose | Judge runs **deterministic-only**; LLM roles are driven by orchestrated subagents at build time |
| `OPENROUTER_API_KEY` | The primary Red Team mutator (Hermes 4 405B, a different model family from the Claude judge) | The mutator falls back to Claude, or to the deterministic keyless transforms with no key at all |

**Getting a session cookie:** sign in as a physician on a deployed Co-Pilot (the original deployment is offline today), open DevTools → Application →
Cookies, and paste the session cookie into `AGENTFORGE_SESSION_COOKIE`. Auth is abstracted behind a
pluggable `SessionProvider` (anonymous / env-cookie / OAuth-automation stub), so swapping in
automated SMART/OAuth login later touches no attack code.

**Local target (optional, free/unlimited iteration):** point `ADVERSARYFORGE_TARGET_BASE_URL` at a
locally stood-up Co-Pilot in `auth_mode=disabled` (no login). See the target repo for standup.

The target has **no inbound rate limiting**, so the platform **self-throttles** (`MAX_CONCURRENCY`,
`MIN_REQUEST_GAP_S`) to avoid becoming the thing that takes the target down.

---

## Layout

```
adversaryforge/
  config.py            # all secrets/tunables (pydantic-settings, reads .env)
  target/              # adapter (endpoint map + safety invariants), session, throttled client
  contracts/           # versioned typed inter-agent messages (pydantic v2)
  agents/              # judge (deterministic + info-barrier), orchestrator, documentation
  redteam/             # seed model/library + executor (multi-turn + bounded burst)
  harness/             # regression & validation harness
  llm/                 # Anthropic client, LLM adjudicator, mutator, pricing (key-gated)
  observability/       # SQLite exploit DB + run log + coverage/cost metrics
  platform.py          # wiring: run a campaign end-to-end
  cli.py               # entrypoint
contracts/             # published JSON Schemas (versioned) + producer/consumer map
evals/seeds/           # adversarial seed suites (unauthenticated + staged authenticated)
reports/               # generated vulnerability reports
docs/                  # target profile, pinned OpenAPI, architecture packets, build ledger
```

## Testing

```bash
.venv/bin/pytest -q
```

The suite includes the **Judge ground-truth set** (validates the deterministic evaluator and
enforces the invariant *a held defense is never labeled a success*) and **contract tests** (both
producer and consumer conform to the published schemas; a model change without a re-export fails).

## Scope & ethics

Only test systems you own or are explicitly authorized to test. The AgentForge deployment above is
the author's own system. Do not point this platform at third-party systems.
