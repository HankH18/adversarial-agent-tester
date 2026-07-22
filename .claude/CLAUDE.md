<!-- BEGIN operating-model (managed by the operating-model skill — edit above/below these markers, not between) -->
## Operating model — how this agent works

This section is **operational conduct** (how to work), kept separate from what the project *is* (that
lives in the root `CLAUDE.md` and the project docs). It loads every session and is authoritative for
working style. Project-specific nouns below are tailored to **this** repo.

### Memory hygiene — lean and goal-first
- Curate the file-based memory actively and **compact it at natural stopping points**. Lead with the
  overarching goals, deadlines, and current status — the things **not** derivable from the code.
- Treat code structure and `file:line` facts as **low priority**: re-derive them with a fresh scan
  rather than storing them (they go stale fast). Never store what the repo, git history, or these
  docs already record.
- One fact per memory file; **update the existing file rather than duplicating**; convert relative
  dates to absolute; keep `MEMORY.md` a one-line-per-entry index.

### Verify live — a green suite is not "done"
- The suite here is **`.venv/bin/python -m pytest`**; a green run means the code did what the tests
  asked — **not** that the live target behaves. Before claiming anything works, is fixed, or shipped,
  **read the effect back from the real system**: run the real end-to-end flow, hit the live target
  (**`https://agentforge.hankholcomb.com`**, synthetic data only — never real PHI), re-capture the
  evidence. *(skills: `verify-the-deploy`, `stub-blindness`)*
- **Measure before you push, not after.** Report outcomes faithfully: if it failed, say so with the
  output; if a step was skipped, say that; distinguish **OBSERVED** (you ran it) from **INFERRED**.

### Change discipline
- **Reproduce a defect before fixing it**, and **prove the fix bites** — sabotage it in place and watch
  the relevant test go red, then restore.
- **Never turn a red test green by editing the test.** That requires overwhelming evidence the *test*
  is wrong, not merely that it is failing, strict, or inconvenient. *(skill: `justify-test-edit`)*
- "Nothing found" is a valued answer; a fabricated finding is worse than none. This is an adversarial
  security tool — a false "we found a vuln" is more damaging than a missed one.

### Investigate and verify with sub-agents
- Fan out **read-only explorers** for broad searches; spawn **skeptical, independent verifiers** for
  findings, each prompted to *refute*. Adversarially verify a claim before you commit to it. (This is
  the audit-loop discipline the platform itself is built on — apply it to our own code too.)
- This repo **is** CodeGraph-indexed (`.codegraph/` exists) but has **no** `UserPromptSubmit` codegraph
  hook, so it won't inject itself — run `codegraph explore "<question>"` **explicitly** before grep/find.
- The read-only target reference at `../openemr-base-clean` is an **inert target**: read it for recon,
  but do **not** adopt its OpenEMR/PHP tooling, git-worktree rules, or week-based doc conventions here.

### Autonomy and cadence
- For long unattended stretches: **work the queue, don't block on review**, and leave a clear wake-up
  summary of what changed and what's next.
- **Outward-facing or hard-to-reverse actions** (deploy, push to either remote, delete, overwrite,
  anything that leaves the machine or hits a third party) **wait for the user** unless explicitly
  pre-authorized.
- When you have enough to act, **act** — give a recommendation, not an exhaustive survey. Don't
  re-litigate settled decisions or narrate options you won't take.

### Keep the workspace clean
- Temp files, probe scripts, and scratch output go in the **session scratchpad**, not the repo.
- Never commit secrets: `.env`, `LIVE_FINDINGS.md`, and `*.sqlite` are git-ignored — verify staged
  files before every commit.
- Conventional-commit messages; **branch before committing on the default branch (`main`)**;
  commit/push **only when asked**.

### Capture what you learn
- When an operational insight **proves out during a run**, fold it into the relevant *living* doc —
  here `ARCHITECTURE.md`, `THREAT_MODEL.md`, `LIVE_FINDINGS.md`, or `reports/` — not just chat. Once
  validated ("and it works"), not speculatively. The next agent should inherit it.

### Doc currency — lightweight (no weekly cadence)
- If a doc is **not** under `archive/`, it is current and authoritative. `archive/**` is superseded
  history — **do not read, grep, or glob it by default.**
- When you supersede a doc, **move the old version into `archive/` in the same change** that adds the
  new one. Never leave two live versions on the active surface.
- No `week-N` folders and no rollover ritual — just **active vs. archived**. (If hard enforcement or a
  weekly cadence is ever wanted, that is the separate `doc-archive` skill; this stays deliberately
  lightweight.)
<!-- END operating-model -->
