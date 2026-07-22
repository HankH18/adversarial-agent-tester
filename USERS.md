# USERS.md — Who AdversaryForge is for, and why it must be automated

> **Submission deliverable.** The users AdversaryForge addresses, their workflows, their specific use
> cases, and — for each — the explicit justification for *why an autonomous multi-agent platform is the
> right solution* rather than manual penetration testing or a static payload list. Every capability
> referenced here maps to a section of `ARCHITECTURE.md`; every target fact is traceable to
> `../openemr-base-clean` via `docs/target/TARGET_PROFILE.md`.

---

## Summary — the shape of the problem the users share

The Clinical Co-Pilot (`https://agentforge.hankholcomb.com`) is not a static web app. It is an
LLM application whose behavior changes with every model version, every prompt-template edit, every new
tool, and every multi-turn conversation. Its richest attack surfaces are *behavioral*: 40-turn verbatim
history replay, uploaded-document field values concatenated into the prompt with no instruction-defusing,
free-text prose the critic does not hard-screen (`TARGET_PROFILE.md`; `ARCHITECTURE.md §3`). Those
surfaces cannot be secured by finding one jailbreak once. They shift under you.

That single fact reorganizes the humans around the system into four users with one shared enemy —
**drift**. The **AppSec engineer** cannot re-run a manual campaign every time the model updates. The
**Co-Pilot engineering team** cannot trust a red test unless a failure means "a real regression," not
"the model felt different today." The **CISO** cannot authorize a tool to attack a system physicians
depend on unless autonomy is bounded, auditable, and cost-governed. The **compliance/ATO reviewer**
cannot sign an authorization without evidence, lineage, and access control that a static list never
produces.

AdversaryForge is built for those four users specifically, and the case study's north star is the
fourth-and-first pair: *a deliverable you could defend in front of a hospital CISO deciding whether to
trust this with continuous testing of systems their physicians depend on.* This document ties each
user's day-to-day workflow to the platform capabilities that serve it — the **independent Judge**, the
**mutation of partial attacks**, **regression that means something**, **deterministic-by-default**
execution, the **cost governor**, the **observability substrate**, and the **human approval gates** —
and makes the why-automation argument concrete for each.

---

## Persona 1 — The Hospital AppSec / Red-Team Engineer

**Role.** Owns offensive security for the hospital's AI-assisted clinical tooling. Formerly ran
quarterly manual pentests and maintained a spreadsheet of known jailbreak strings. Now responsible for
*continuous* adversarial coverage of a Co-Pilot that ships changes weekly.

**Goals.**
- Keep every threat-model category under continuous attack, not just the one they had time for this
  sprint.
- Turn a *partial* success (a payload that got 80% of the way) into a confirmed exploit without hand-crafting
  the last 20% themselves.
- Produce findings an engineer can act on, with reproduction that survives a model update.

**A day with the platform.**
1. Morning: opens the observability dashboard (`ARCHITECTURE.md §11`) and reads the coverage table —
   which of the six threat-model categories (prompt injection, PHI exfiltration, state corruption, tool
   misuse, DoS/cost, identity/role) are stale, which have open high-severity findings, which just
   regressed. They do not decide what to test; the **Orchestrator's deterministic priority score**
   (`§6`) already ranked it, and they read the *why*.
2. They kick off an overnight campaign. The **Red Team Agent** (`§4.2`) runs tree/iterative search over
   the highest-priority category, and — this is the leverage — when an attempt comes back *partial*, the
   **Mutator** autonomously expands it into a family of variants (rephrase, encode, role-shift, split
   across turns, embed in an uploaded document) without the engineer writing a single one.
3. Overnight the platform runs unattended. The **cost governor** (`§10`) halts any campaign burning
   tokens without producing signal, so the engineer does not wake up to a bill or a wasted run.
4. Morning after: the **Judge** (`§4.3`) has independently confirmed the real hits, the **Documentation
   Agent** (`§4.4`) has drafted reports, and anything critical is waiting at the **human approval gate**
   (`§8`) for the engineer's sign-off. Their job shifts from *generating* attacks to *adjudicating* the
   platform's confirmed findings.

**Specific use cases.**
- *Continuous multi-turn probing.* Seed one near-miss injection; the Mutator turns it into ten
  multi-turn escalations against the 40-turn verbatim-replay surface overnight (`§3`, `§4.2`).
- *Indirect-injection via documents.* Point a campaign at the upload surface; the Red Team embeds
  instructions in document field values that are concatenated into the prompt (`TARGET_PROFILE.md`).
- *Near-miss escalation.* Feed the prior-attempt/verdict history back into the Strategist so it escalates
  what almost worked instead of re-trying what already failed (`§4.2`).

**Why automation, not manual pentesting or a static list.** A human red-teamer can craft a brilliant
jailbreak — once. What they cannot do is craft it, then craft the ten mutations, then re-run all eleven
every time the model version changes, across six categories, every night, forever. The measured
jailbreak gains in the literature come from *search and iteration* — TAP-style tree search buys ~36
attack-success points over a single-branch chain (`§4.2`) — which is exactly the mechanical, high-volume
work humans are worst at sustaining and machines are best at. A static payload list is worse still: the
target's maintainer has already run two adversarial passes and fixed the low-hanging bugs
(`TARGET_PROFILE.md`), so yesterday's list is already stale. Static lists *become outdated quickly;
defenses built around a small number of known examples rarely hold as attackers adapt* (case study, p.4).
The engineer's scarce judgment is spent on the confirmed finding, not on typing variants.

---

## Persona 2 — The Clinical Co-Pilot Engineering Team

**Role.** Builds and ships the Co-Pilot. Consumes AdversaryForge's output as a *supplier of security
signal*: vulnerability reports to fix, and a regression gate wired into CI that must block a merge when —
and only when — a real vulnerability reappears.

**Goals.**
- A red regression test that means "we broke something," not "the model was moody."
- Reports an on-call engineer who never saw the exploit can reproduce and fix from the text alone.
- Confidence that fixing one category did not silently reopen another.

**A day with the platform.**
1. A developer opens a PR that changes the chat prompt template. CI triggers the **Regression &
   Validation Harness** (`§4.5`, `§7`), which replays every confirmed exploit against the new build.
2. One case goes red. Because the harness's pass criterion is *the same deterministic assertion the Judge
   used to confirm the exploit* — and the shipped gate is **fail-closed** (an inconclusive/errored run
   never reads as fixed) — the red is trustworthy, not a stochastic flip. (An **N-times stability replay**
   to fingerprint flaky cases is planned — see `AS_BUILT.md`; the current gate re-judges deterministically.)
3. The developer opens the linked **vulnerability report** (`§4.4`): unique ID, severity, minimal
   reproduction sequence lifted *verbatim from the transcript* (not regenerated by an LLM, so repro
   fidelity does not depend on model mood), observed-vs-expected, and a recommended remediation.
4. They ship the fix. The harness re-runs the **full** suite, not just the fixed case, and confirms the
   fix did not flip a previously-green case in another category to red — the cross-category regression
   check (`§7` step 5).

**Specific use cases.**
- *Merge gate that means something.* A red test in CI blocks the merge because the exploit assertion
  fired again and held across N replays — distinguishing a real regression from behavioral drift
  (`§7`, and the invariant *a passing regression test must mean the vulnerability is fixed* — `§2`).
- *Reproduce-from-report.* An on-call engineer fixes a finding at 2 a.m. from the report's minimal
  sequence alone, because repro steps are ground-truth transcript, not LLM prose (`§4.4`, `§13`).
- *Fix-validation loop.* After a patch, the report's status and fix-validation fields update from the
  harness automatically; the finding re-enters observability as resolved, and the Orchestrator schedules
  a re-test (`§4.4`, `§11`).

**Why automation, not manual pentesting or a static list.** This team's core need is a *test that means
something*, and that is precisely what a static list and a manual pentest cannot give an LLM system. A
static assertion like "the model refused" goes green the moment the model's phrasing changes — *a test
that passes because the model's behavior changed, not because the vulnerability was fixed, is worse than
no test at all* (case study, p.10). AdversaryForge earns the trust by construction: the pass criterion is
the exact deterministic assertion that confirmed the exploit (the target exposes a machine-checkable
`verification.action` field — `§3`), re-run N times for stability, cross-checked against the full suite.
A manual pentester who validates a fix once and moves on cannot detect the variant that bypasses it three
weeks later; the platform re-runs the whole corpus on every deploy, forever. The team gets a CI gate they
can actually block merges on — the thing a spreadsheet of payloads can never become.

---

## Persona 3 — The Hospital CISO (the north-star reader)

**Role.** Accountable for whether an *autonomous* system is permitted to continuously attack production
clinical tooling that physicians use during rounds. Signs, or refuses to sign, the authorization. This
is the reader the case study names as the standard: *the deliverable that matters is the one you could
defend in front of a hospital CISO deciding whether to trust this platform with continuous security
testing of systems their physicians depend on.*

**Goals.**
- Bounded blast radius — certainty the platform cannot mutate a patient record or take the Co-Pilot down.
- Auditability — a full reconstruction of what every agent did during an unattended overnight run.
- Human control at the decisions that matter, and predictable cost.

**A day with the platform.**
1. Before authorizing, the CISO reviews the **trust model** (`§8`): the Red Team holds *read/interact-only*
   credentials with **no write scope**, egress-restricted to the target host and the model provider; the
   platform **never** calls the target's `/v1/writes*` routes (a design exclusion, not a togglable
   permission); and it is write-only against its *own* database, never the target (`§2` principle 3).
2. They inspect the **human approval gates**: nothing critical publishes without a
   security engineer's sign-off; re-targeting to any host not on the human-owned allow-list is gated;
   budget overrides are a logged human decision (`§8`). Autonomy stops exactly at the blast radius.
3. They review the **cost governor** (`§10`): per-agent, per-campaign metering with a no-signal halt, so
   an overnight run cannot silently run up a bill — cost is a first-class control, not a postmortem.
4. Post-authorization, when an incident review is needed, they pull the **per-agent ordered trace**
   (`§11`): every finding is traceable back through the Red Team attempt, the Judge verdict, and the
   Documentation report that produced it. Every PHI read the platform made also landed in the target's
   own append-only `audit_log` (`§8`).

**Specific use cases.**
- *Authorize with a bounded blast radius.* Sign off knowing the attacker literally cannot write to a
  clinical record and the platform self-throttles so it does not become the DoS it is testing for
  (`§8`, `§10` — the target has *no inbound rate limiting*, so the platform imposes its own).
- *Trust the verdicts.* Rely on findings because the **Judge is independent by construction** — it is fed
  only a `JudgeView` (the transcript + the invariant under test), *never* the attacker's technique, intent,
  or self-assessment, and it is **deterministic-first** so most verdicts don't depend on any model at all
  (`§4.3`). An attacker cannot talk the Judge into a false positive. (Two hardening legs are planned, not
  yet shipped — a *different-family* attacker model and a per-run *Cohen's-κ* drift gate; both are
  disclosed in `AS_BUILT.md`. Anti-drift today is the versioned ruleset + the ground-truth test set.)
- *Reconstruct any overnight run.* Answer "what did the platform do at 3 a.m. and why" from the trace and
  the deterministic decision log — target selection is a *scoring function*, not an LLM's "it felt
  important" (`§6`).

**Why automation, not manual pentesting or a static list.** This is the persona where the naive intuition —
"a human is safer than an autonomous agent" — is exactly backwards, and the platform's design is the
argument. A CISO's real fear is not autonomy; it is *unbounded* autonomy and *unauditable* action. A
manual pentest gives you a point-in-time snapshot and a human's memory of what they tried; it gives you
neither continuous coverage nor a machine-reconstructable record. AdversaryForge gives the CISO what a
human red team cannot: **deterministic-by-default** execution so every decision is reproducible and
explainable; **structural** trust boundaries so autonomy provably stops at the blast radius; **human
gates** placed exactly where a wrong autonomous call is expensive; a **cost governor** that makes spend
predictable; and an **observability substrate** that makes an unattended run more auditable than a
manual one, not less. The reason to trust *this* automation is that every AI decision is followed by a
deterministic check, a human gate, or both (`§9`, `§13`) — *the AI proposes; deterministic code disposes.*
A static list, meanwhile, offers no audit trail at all and stops testing the moment the threat evolves.

---

## Persona 4 — The Compliance / ATO Reviewer

**Role.** Grants (or withholds) the Authority to Operate. Does not evaluate cleverness; evaluates
*evidence*. Needs the artifact a security reviewer would actually accept: architecture and data-flow
diagrams, an auth model, a dependency inventory, self-scan results, test evidence, data lineage, access
controls, and a sample incident/postmortem.

**Goals.**
- A complete, versioned evidence packet — not a demo.
- Data lineage: which agent produced which record, and traceability of every finding.
- Enforced access control on the platform's own data, and a documented data-quality contract.

**A day with the platform.**
1. The reviewer opens the **ATO-style evidence packet** (`ARCHITECTURE.md §16` #7; `docs/architecture/ATO_PACKET.md`):
   architecture diagram, data-flow diagram, the **auth model** table (which agent may call which target
   with which credentials — `§8`), a dependency list with versions, the platform's own self-scan results,
   eval/test evidence, and a sample postmortem.
2. They verify **access control on the exploit database** (`§12`): the Judge and Harness *write*
   exploits/cases; the Orchestrator *reads* them; the Documentation Agent writes reports *behind the human
   gate for critical*. Read-vs-write is enforced by the auth model, not convention.
3. They check the **data-quality contract** enforced *before* any report is written (`§12`; `§4.4`):
   every confirmed exploit has a unique ID, all required fields (severity, category, reproduction steps,
   observed and expected behavior), and no duplicate entry for the same attack sequence — validated
   deterministically in the Documentation Agent.
4. They confirm **data lineage** from the per-agent ordered trace (`§11`): any published finding is
   traceable back through the exact agents and messages that produced it, and every inter-agent message
   conforms to a **versioned JSON-Schema contract** in `/contracts` with typed error schemas (`§5`).

**Specific use cases.**
- *Assemble an evidence packet for ATO.* Hand the reviewer a packet with auth model, DFD, dependency
  versions, self-scan, and postmortem already assembled as a submission artifact, not reverse-engineered
  after the fact (`§16`; `ATO_PACKET.md`).
- *Prove data lineage and access control.* Demonstrate that only the Judge/Harness write findings, the
  Orchestrator only reads, and critical publication is human-gated — the access-control table maps to the
  auth model (`§8`, `§12`).
- *Verify the data-quality and versioning contract.* Show unique-ID/required-field/no-duplicate
  enforcement and versioned schemas with migration notes, so records survive a report-format change
  without loss (`§12`, `§5`).

**Why automation, not manual pentesting or a static list.** An ATO reviewer's currency is *reproducible,
lineage-bearing evidence*, and this is where manual testing and static lists fail hardest. A manual
pentest produces a PDF a human wrote from memory; there is no machine-enforced lineage tying a finding to
the process that produced it, no versioned contract, no enforced data-quality invariant, no
reconstructable trace of an unattended run. A static payload list produces a pass/fail with no provenance
at all. AdversaryForge is *designed as an evidence substrate*: the observability layer is built as an
input, not a dashboard bolted on afterward (`§11`); every inter-agent hand-off is a versioned, typed,
independently-testable contract (`§5`); the exploit DB enforces data quality before write and supports
lossless migration (`§12`); and access control is structural. The reviewer gets an auditable pipeline
whose every record can be traced to its origin — the artifact a security reviewer *would accept* — which a
one-time human engagement or a flat list of strings can never be.

---

## Cross-persona: the capability-to-user map

| Platform capability (`ARCHITECTURE.md`) | AppSec | Co-Pilot Eng | CISO | ATO Reviewer |
|---|:--:|:--:|:--:|:--:|
| Independent Judge (transcript-only `JudgeView`, deterministic-first; different-family + κ-gate planned) — `§4.3` | ● | ● | ● | ● |
| Mutation of partial attacks (Mutator; tree search planned) — `§4.2` | ● | | | |
| Regression that means something (assertion re-run; N-replay stability planned) — `§7` | | ● | ● | ● |
| Deterministic-by-default (AI proposes, code disposes) — `§9` | | ● | ● | ● |
| Cost governor (per-agent metering, no-signal halt) — `§10` | ● | | ● | |
| Observability substrate (per-agent ordered trace, lineage) — `§11` | ● | ● | ● | ● |
| Human approval gates (critical publish, re-target, budget) — `§8` | ● | | ● | ● |

The single through-line: **manual pentesting and static payload lists solve a one-time problem, and the
Clinical Co-Pilot is a continuously-changing one.** Every user above shares the same adversary — drift —
and each capability exists to beat it for a specific user: mutation beats a static list for the AppSec
engineer, meaningful regression beats behavioral drift for the engineering team, bounded auditable
autonomy beats an untrusted black box for the CISO, and lineage-bearing evidence beats a hand-written PDF
for the ATO reviewer. That is why the right solution is an autonomous multi-agent platform, not a person
with a checklist.
