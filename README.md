# AdversaryForge

**A multi-agent adversarial evaluation platform that continuously hunts, evaluates, and documents
vulnerabilities in AI-assisted clinical chatbots.** Target #1 is the OpenEMR **Clinical Co-Pilot**
(AgentForge) — a live, authorized, synthetic-data-only deployment.

> The goal is not to find one jailbreak. It is a system that can tell — run after run, version after
> version — whether a *category* of exploit is still open, whether a fix actually held, and whether
> closing one hole opened another. Built to the standard of *a hospital CISO deciding whether to
> trust it with continuous testing of systems their physicians depend on.*

- **Deployed target under test:** https://agentforge.hankholcomb.com (authorized — user-owned;
  synthetic demo data only, never real PHI)
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) · **Threat model:**
  [`THREAT_MODEL.md`](THREAT_MODEL.md) · **Users:** [`USERS.md`](USERS.md)
- **Build ledger (historical, per-cycle):** [`docs/BUILD_LEDGER.md`](docs/BUILD_LEDGER.md) — for the current test count run `.venv/bin/python -m pytest -q`

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

```bash
# 1. Set up the environment (uv — or the plain-pip fallback just below)
uv venv --python 3.12
uv pip install -e '.[dev]'
#    No uv?  python3.12 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# 2. Configure (both secrets are OPTIONAL — the platform runs without them)
cp .env.example .env      # then edit — see "Authentication & keys" below

# 3-6. Run the platform (from the repo root)
#    NOTE: the SQLite store is git-ignored and starts EMPTY, so status/regress/trace
#    show nothing until `campaign` has populated it — run campaign first.
.venv/bin/python -m adversaryforge.cli campaign   # attack the live target
.venv/bin/python -m adversaryforge.cli seed-demo  # populate illustrative findings (fresh-clone demo)
.venv/bin/python -m adversaryforge.cli resume     # resume a crashed/interrupted campaign
.venv/bin/python -m adversaryforge.cli status     # observability snapshot the Orchestrator reads
.venv/bin/python -m adversaryforge.cli report     # (re)generate reports/*.md
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
| `regress` | Re-run confirmed exploits; exits non-zero unless the fail-closed gate is GREEN |
| `report` | (Re)generate professional vulnerability reports |
| `trace [run_id]` | Render the fine-grained per-agent execution trace (span tree) for a run |

---

## Authentication & keys

The platform is designed to run and produce **real evidence without any secrets**, then unlock more
coverage as secrets are provided.

| Secret (`.env`) | Unlocks | Without it |
|---|---|---|
| `AGENTFORGE_SESSION_COOKIE` | The **authenticated** attack plane (prompt injection, PHI exfil, multi-turn) against the deploy | Runs the **unauthenticated** live surface (info disclosure, error-oracle, rate-limit, auth enforcement) |
| `ANTHROPIC_API_KEY` | The platform's **in-process** LLM Red Team mutator + LLM-second Judge + Documentation prose | Judge runs **deterministic-only**; LLM roles are driven by orchestrated subagents at build time |

**Getting a session cookie:** sign in as a physician at the deploy, open DevTools → Application →
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
