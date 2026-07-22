# Demo Script — AdversaryForge (3–5 min)

> A tight, live walkthrough for the submission video. Every step runs against the **live** deployed
> target `https://agentforge.hankholcomb.com`. Rehearse once; the whole thing is ~4 minutes.
> Terminal on the left, `THREAT_MODEL.md` / a `reports/VULN-*.md` open on the right.

**One-line thesis to open and close on:** *"Not a jailbreak finder — a system that tells you, run
after run, whether a category of exploit is still open, whether a fix held, and whether closing one
hole opened another. Built to the standard of a hospital CISO."*

---

## 0. Setup (before recording)
```bash
cd adversarial-agent-tester
uv venv --python 3.12 && uv pip install -e '.[dev]'    # one clean install
rm -f data/adversaryforge.sqlite*                       # fresh baseline for the demo
```
Have these ready to show: `ARCHITECTURE.md` (the agent diagram), `THREAT_MODEL.md`, and a terminal.

---

## 1. The problem & the architecture (~40s — talk over the diagram)
- OpenEMR shipped an AI Clinical Co-Pilot. The risk isn't one jailbreak — it's whether the system can
  *continuously* find, evaluate, and defend as attacks evolve.
- Show `ARCHITECTURE.md` §4 diagram: **four AI agents + two deterministic subsystems.** Name the three
  decisions that carry it: **(1)** the Judge is independent *by construction* — different plane, and it
  only ever sees a `JudgeView` (transcript + invariant), never the attacker's intent. **(2)**
  deterministic by default, AI only where it's irreducible. **(3)** autonomy bounded by blast radius —
  read-mostly against the target, write-only against our own store, human gate before a critical.

## 2. The target is live and auth-gated (~20s)
```bash
curl -s -o /dev/null -w "chat unauth -> %{http_code}\n" \
  -X POST https://agentforge.hankholcomb.com/v1/chat \
  -H 'Content-Type: application/json' -d '{"message":"hi","patient_id":1}'
# -> 401  (per-physician SMART/OAuth; we test what we can reach + stage the rest)
```
Point: real system, real auth. The platform runs the **unauthenticated live surface** now and
**auto-runs the authenticated attack plane** the moment a session cookie is provided.

## 3. Run a live campaign — the multi-agent loop (~70s)
```bash
adversaryforge campaign
```
Narrate as it runs: **Orchestrator** deterministically selected a category → **Red Team** executed the
seed suite against the live target → **Judge** evaluated each response → confirmed exploits stored.
Call out the result line: *3 defenses held (401 authz), 3 confirmed findings, partials mutated.*

Then the **observability substrate the Orchestrator reads**:
```bash
adversaryforge status
```
Point to: coverage per category, pass/fail rates, **resilience trend** (is the target getting more or
less resilient?), open findings, and **cost** (metered per agent).

## 4. A real finding, documented autonomously (~50s)
```bash
adversaryforge report
ls reports/            # 3 VULN-*.md
```
Open one `reports/VULN-*.md` on the right. Point out it's reproducible by an engineer who wasn't there:
unique ID, severity, **clinical impact**, a minimal reproduction with the *actual* request/response,
observed-vs-expected, remediation, OWASP mapping, and a **human-approval banner on criticals**.
(Note: live findings are tracked privately in the git-ignored `LIVE_FINDINGS.md`.)

## 5. Regression that *means something* (~40s)
```bash
adversaryforge regress
```
Narrate: each confirmed exploit was frozen into a replayable case. Re-running re-judges the **invariant**
— so a pass means the vulnerability is genuinely closed, not that the model's mood changed. The gate is
**fail-closed**: a dead/errored target is *inconclusive*, never a false "fixed." Right now the 3
findings are still open → gate NOT GREEN (correct).

## 5b. Deterministic-first, LLM-second — visible in one trace (~30s — strong beat)
```bash
adversaryforge trace          # renders the last run's per-agent span tree
```
Point at two `judge.evaluate` spans side by side: most say **`tier=deterministic` (~0.3ms)** — pure
code decided them; the one the deterministic rules *couldn't* settle escalated to
**`tier=llm-panel → judge.llm_adjudicate → llm.call model=claude-opus-4-8` (~2s)**. That is the whole
"AI only where it's irreducible" thesis in a single screen — and `status` shows the exact USD/tokens
that one call cost. The trace also shows every `target.request` (method/path/status/latency) and, per
Judge decision, the exact `judge.rule` that fired with its rationale.

## 6. The adaptive Red Team (~30s — the differentiator)
Show `adversaryforge seeds` (23 seeds, 6 categories, boundary/invariant/regression roles). Explain the
**mutation loop**: when the Judge returns *partial*, the Red Team autonomously generates N variants of
the attack, re-runs and re-judges each, and promotes any breakthrough — no human telling it what to try
next. (`mutation_breakthrough` events appear on the observability timeline.)

## 7. Close (~20s)
- Recap: distinct agents with distinct trust levels; a Judge that can't be fooled by the attacker;
  determinism where it counts; cost as a first-class signal; human gates at the blast radius.
- End on the thesis: *"The deliverable that matters is the one you could defend in front of a hospital
  CISO deciding whether to trust it with continuous testing of systems physicians depend on. That's
  what this is built to."*

---

## Backup / if a command is slow
- `status` and `report` read local state instantly — lead with those if the live network is slow.
- The 3 findings are deterministic and reproduce every run; if the live campaign stalls, show a
  pre-recorded `campaign` run and pivot to `status`/`report`/`regress` live.

## Talking points to have in your pocket
- **Why not a commercial frontier model for the attacker?** They refuse offensive-security workflows;
  the design routes the Red Team to an open-weight model (Hermes via OpenRouter). See `AS_BUILT.md` for
  the honest current state (Anthropic-only on this build) and the independence caveat + mitigation.
- **Why not just a static payload list?** Attacks mutate; a static list goes stale. The seeds are the
  *seed* the Red Team learns from and extends.
- **How do you know the Judge itself is right?** A versioned ruleset + a ground-truth test set
  (`tests/test_judge_groundtruth.py`) — a verdict change is a visible diff, not silent drift.
