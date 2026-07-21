# Adversarial Agent Tester — orientation

> **The project doc is the source of truth.** Read **`docs/Week_3_AgentForge.md`** — a verbatim text
> extraction of `docs/Week_3_AgentForge.pdf`, provided in markdown because PDFs are not directly
> readable in this environment. It defines the requirements, the hard gates, and the deliverables.
> **Everything in this file is orientation and defaults — not requirements.** Wherever this file, or
> any scaffolding in this repo, conflicts with the project doc, **the project doc wins.**

## What this repo is

A multi-agent adversarial evaluation platform that continuously attacks an AI-assisted clinical
chatbot: discovering vulnerabilities, mutating partially-successful attacks, judging success
*independently* of the attack engine, converting confirmed exploits into regression tests, and
documenting them as professional vulnerability reports.

Target #1 is the AgentForge Clinical Co-Pilot (below). The platform is meant to generalize to "others
like it" — so prefer a **target adapter** (base URL, auth mode, endpoint map, expected safety
invariants) over hard-coding one system's routes.

## The target under test

- **Live deployment — authorized target, the user owns it:** https://agentforge.hankholcomb.com
  Per-physician SMART/OAuth sign-in. Synthetic demo data only; never real PHI.
- **Source repo (read-only reference):** `../openemr-base-clean`, wired in via
  `.claude/settings.json` → `permissions.additionalDirectories`, so it is readable every session with
  no flag. (Assumes the two repos stay siblings and Claude is started from this repo's root.)
- **Pinned contract:** `docs/target/openapi-week2.PINNED.yaml` — a frozen copy of the target's OpenAPI
  spec (24 endpoints). The live target moves; pin what you test against so a red test means "we found
  something," not "the target changed underneath us."
- **Target profile:** `docs/target/TARGET_PROFILE.md` — endpoints, trust boundaries, existing
  defenses, and the target's own documented limitations.

## Reading the target repo efficiently

It is ~9,200 tracked files, and **~95% is upstream OpenEMR the user did not write.** Read on demand;
do not crawl it.

**High value:**
- `agent/copilot/` — the actual agent. This *is* the attack surface.
- `agent/openapi/week2.yaml` — the live API contract.
- `W2_ARCHITECTURE.md`, `WALKTHROUGH.md` — architecture and per-feature flows. `WALKTHROUGH.md §6` is
  a list of the target's *own* documented weaknesses — a strong place to start a threat model.
- `agent/COMPLIANCE.md`, `OBSERVABILITY.md` — the safety **claims**, i.e. the things an adversarial
  suite exists to try to falsify.
- `.swarm-loop/acceptance/`, `agent/evals/` — what the target *already* tests, so effort can aim at
  the gaps rather than re-proving covered ground.

**Ignore** (upstream OpenEMR, not the system under test): `src/`, `interface/`, `library/`, `portal/`,
`Documentation/`, `ccdaservice/`, `templates/`, and the PHP `tests/`.

The reference repo is CodeGraph-indexed — running `codegraph explore "<question>"` from that
directory is far cheaper than grepping thousands of files.

> The reference repo's own `CLAUDE.md` does **not** load into this session (Claude Code does not load
> memory files from additional directories). That is intentional: its OpenEMR-dev instructions — PHP
> tooling, git worktrees, the doc-archive convention — do not apply to this project.

## Scope and ethics

Only test systems the user owns or is explicitly authorized to test. The AgentForge deployment above
is the user's own system. Do not point this platform at third-party systems.
