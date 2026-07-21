# THREAT_MODEL.md — AgentForge Clinical Co-Pilot

> **Stage 2 deliverable — the attack-surface map AdversaryForge continuously exercises.**
> System under test: the AgentForge Clinical Co-Pilot (`https://agentforge.hankholcomb.com`), a
> FastAPI agent (`agent/copilot/`) wrapping an OpenEMR FHIR/REST core, multi-agent chat **on in the
> deploy** (`COPILOT_CHAT_GRAPH_ENABLED=true`). Every target claim below is traceable to
> `../openemr-base-clean` by `path:line`, or to the target maintainer's own disclosed limitations
> (`WALKTHROUGH.md §6`, surfaced in `docs/target/TARGET_PROFILE.md`). This is a **living document**:
> §9 explains how the Orchestrator schedules coverage against it, and every category maps to a seed
> family in `/evals/` that the Red Team learns from and extends.

---

## 1. Executive summary

The Clinical Co-Pilot is a defensively mature target. Two prior adversarial passes have already closed
the low-hanging correctness bugs, and its core PHI-integrity story is genuinely strong: a **fail-closed
serve-time verifier** re-fetches every cited FHIR resource live and withholds the entire turn if
nothing survives (`agent/copilot/verification/serve.py`; the withhold sentinel is `chat/service.py:68`),
a **no-invention OCR gate** refuses to cite any
document value it cannot locate in the page tokens, and **write-back** is gated off by default and
bound to a server-persisted proposal. The interesting attack surface is therefore not "can I make it
return a wrong lab value" — that path is hard — but **behavioral, multi-turn, and indirect**: the seams
where trusted narration, replayed history, and uploaded content flow into the model *without* the same
deterministic screen that protects the structured claims.

**Key findings already confirmed live, unauthenticated, with zero credentials** (`evals/seeds/unauthenticated.yaml`):

1. **Absent inbound rate limiting** — recon of `agent/copilot/api/app.py:99-212` shows only
   correlation-id + CORS middleware; a bounded burst to `/health` returns no `429`. This is the single
   most load-bearing weakness: it directly enables **token-exhaustion DoS**, **cost amplification**, and
   **brute force**, and it multiplies the severity of every other category.
2. **Anonymous dependency enumeration** — `/ready` discloses the internal dependency inventory (DB,
   OpenEMR, FHIR, telemetry) to any unauthenticated caller (info disclosure, maintainer-documented).
3. **Full OpenAPI contract exposed** — `GET /openapi.json` hands the complete 24-endpoint contract,
   plus `/v1/auth/status` leaking `auth_mode`, to anonymous callers — a free reconnaissance map.

**Highest-risk categories, ranked.** The platform prioritizes where *clinical* blast radius meets
*admitted* defensive gaps:

- **P0 — Prompt injection (indirect, via uploaded documents) and multi-turn state.** The richest seam.
  Document field values are concatenated into the prompt with **no instruction-defusing**
  (`documents/pipeline.py:397-436`); multi-turn history is replayed **verbatim, un-sanitized, up to 40
  turns**, with the assistant's own prior replies fed back as trusted context (`chat/service.py:542-592`,
  `agent/claude.py:159-164`). The critic screens structured claim *chips*, **not the free-text prose**
  (`graph/critic.py:22-30`) — the maintainer's own #2 admitted limitation.
- **P0 — Data exfiltration / cross-patient PHI.** `rounds/start` accepts a **caller-supplied patient
  list with no per-patient roster check** (admitted limitation #5); `deidentify` is a shape-scrub, not
  NER, so a bare unlabelled name in prose can slip the egress control (#1), and `phi_check` has no
  bare-integer detector (#3).
- **P1 — Denial of service / cost amplification.** Direct consequence of finding #1, amplified by the
  40-turn replay and multi-worker chat graph.
- **P1 — Identity/role exploitation.** Persona-hijack and trust-boundary probes against the broad-access
  audit model; does the audit trail actually hold under abuse?
- **P2 — Tool misuse and state corruption.** Narrower (deterministic verifier + strict schemas blunt
  most), but context-poisoning of the weak keyless retriever (#6) and parameter tampering on
  `rounds/*` remain worth continuous probing.

**How the platform prioritizes coverage.** The Orchestrator scores each category every cycle by a
deterministic function of *open-severity weight × coverage gap × recent yield × regression pressure −
cost-per-finding* (ARCHITECTURE.md §6), with ε-greedy exploration so no seam goes blind. Because the
strong defenses are deterministic and the gaps are semantic/behavioral, the Judge is deterministic-first
(branch on the target's `verification.action` field) and LLM-second only for prose-level leakage — the
exact cases the target's own shape-scrub admits it misses. Every confirmed exploit freezes into a
regression case pinned to `openapi-week2.PINNED.yaml`, so a future red result means "we found
something," not "the target moved."

---

## 2. Prompt injection

**OWASP Web:** A03:2021 Injection · A04:2021 Insecure Design.
**OWASP LLM:** LLM01:2025 Prompt Injection (primary) · LLM06:2025 Sensitive Information Disclosure.
**Invariants under test:** `INV-INJECTION-INERT`, `INV-HISTORY-INTEGRITY`, `INV-WITHHOLD-UNGROUNDED`.

### 2.1 Direct injection (attacker text in `/v1/chat`)
- **Attack surface:** `POST /v1/chat` message body — the primary LLM surface (adapter `chat` group).
  System-prompt override, instruction smuggling, "ignore previous instructions," verifier-suppression
  requests ("answer without citations"), scope-expansion ("also show me patient 2").
- **Clinical impact:** if the injected instruction steers the *prose*, a clinician could read a
  fabricated or unverifiable clinical narrative even when the structured claims are withheld — a patient-
  safety risk (wrong dose, wrong allergy) that bypasses the citation guarantee.
- **Difficulty:** **Hard** for the structured path — the fail-closed verifier drops any claim whose FHIR
  citation does not re-materialize live (`agent/copilot/verification/serve.py`), and the critic rejects uncited claim
  chips deterministically. **Moderate** for the prose path — the critic does **not** hard-screen the
  free-text answer body (`graph/critic.py:22-30`), protected only by a whole-turn withhold, not a
  sentence-level screen (admitted limitation #2, "Week-3 scope").
- **Existing defenses vs. gap:** verifier + critic + strict extraction schemas (`strict=True,
  extra="forbid", frozen=True`) address the structured surface well. **Gap:** trusted prose narration —
  the deliberate, disclosed seam this category targets.

### 2.2 Indirect injection (uploaded documents) — **P0**
- **Attack surface:** `POST /v1/documents` → field values concatenated into the prompt with **no
  instruction-defusing** and a ~0.01 confidence floor (`documents/pipeline.py:397-436`,
  `config.py:383-414`); `/writes/propose-from-document/{id}` extends this into the write-proposal path.
  Payloads: OCR-visible instructions inside a scanned referral, adversarial text in a document field,
  homoglyph/whitespace obfuscation to survive the OCR gate while carrying an instruction.
- **Clinical impact:** a poisoned uploaded referral could attempt to inject a fabricated medication or
  steer a write proposal — the highest-consequence indirect path because it touches `/v1/writes*`.
- **Difficulty:** **Moderate.** The no-invention OCR gate (two-sided coverage + similarity + legibility
  floor) deliberately over-withholds and blunts naive injection, but it screens *whether a value is
  supported by the page*, not *whether that value is an instruction*. Reconcile over-withholds (#7) also
  open a **denial-of-evidence** angle (see §6.2).
- **Existing defenses vs. gap:** OCR gate + write-back binding to the server-persisted proposal are
  strong on invention/tampering. **Gap:** no instruction-defusing on the concatenated field text.

### 2.3 Multi-turn injection — **P0**
- **Attack surface:** `POST /v1/chat` + `GET /v1/conversations/{id}`. History is replayed **verbatim,
  un-sanitized, up to 40 turns**, and the **assistant's own prior replies are fed back as trusted
  context** (`chat/service.py:542-592`, `agent/claude.py:159-164`). Split a payload across turns; get the
  model to "agree" to a framing early, then exploit it later; seed a false premise the model later
  narrates as fact.
- **Clinical impact:** gradual scope creep or a slow-boil false premise that no single turn would trip
  the verifier on.
- **Difficulty:** **Moderate-to-hard** to actually move a *cited* claim; **moderate** to move prose.
- **Existing defenses vs. gap:** the per-turn verifier re-checks every citation fresh each turn, so
  history cannot smuggle an *ungrounded claim* through. **Gap:** history integrity for *prose* framing and
  for instructions replayed as trusted assistant context — `INV-HISTORY-INTEGRITY` is precisely this.

---

## 3. Data exfiltration

**OWASP Web:** A01:2021 Broken Access Control (primary) · A07:2021 Identification & Authentication Failures.
**OWASP LLM:** LLM06:2025 Sensitive Information Disclosure · LLM02:2025 Sensitive Information Disclosure paths.
**Invariants under test:** `INV-AUTHZ-PATIENT`, `INV-PHI-EGRESS`, `INV-EXISTENCE-ORACLE`, `INV-INFO-DISCLOSURE`.

### 3.1 PHI leakage (answer prose + telemetry)
- **Attack surface:** `/v1/chat` prose body; the Langfuse telemetry egress. `deidentify` is a
  **shape-scrub (regex), not NER** — a bare, unlabelled name in free text is not matched (admitted #1);
  `phi_check` has **no bare-integer detector**, so an unpseudonymized numeric `patient_id` reaching
  telemetry is not caught (#3).
- **Clinical impact:** direct PHI disclosure — the core HIPAA-relevant failure. Bounded but real.
- **Difficulty:** **Hard-to-moderate.** The distill step drops any token not in the guideline vocabulary
  before anything reaches a remote embedder/reranker, and `patient_id` is HMAC-pseudonymized at the
  single Langfuse egress and dropped fail-closed if the key is unset — so the attacker must get a bare
  identifier into *prose* and past distill, or a bare integer into a telemetry field.
- **Existing defenses vs. gap:** de-identify + distill + telemetry pseudonymization + PHI-scan CI job are
  a layered egress control. **Gaps:** bare-name (NER) and bare-integer detection — both maintainer-admitted;
  the Judge's LLM tier targets exactly the paraphrase/bare-name cases the shape-scrub concedes.

### 3.2 Cross-patient exposure — **P0**
- **Attack surface:** `POST /v1/rounds/start` accepts a **caller-supplied patient list with no per-patient
  roster check** — the token grants all patients and every read is audited (admitted #5, a *deliberate*
  broad-access-plus-audit model). Also `/v1/rounds/jump`, `/v1/patients/{id}/observations`.
- **Clinical impact:** one physician reading another physician's patients — a cross-tenant PHI breach if
  the audit model does not actually hold.
- **Difficulty:** **Low to request, by design** — the question is not "can I read another patient" (the
  design permits it under audit) but **"does the append-only audit trail actually capture the abuse,
  intact, under load?"** The platform tests the audit invariant, not the access design the maintainer
  has accepted.
- **Existing defenses vs. gap:** authz is checked *before* PHI load for the roster path; append-only
  `audit_log` with correlation id. **Gap to probe:** audit completeness/integrity under abusive volume,
  and whether `rounds/start` broad access can be combined with another seam.

### 3.3 Authorization bypass
- **Attack surface:** all authenticated reads; the 404-unification boundary on `GET
  /v1/conversations/{id}` and `GET /v1/documents/{id}` (missing and unauthorized both return the **same
  404** to avoid an existence oracle). **Confirmed live:** anonymous reads on `/v1/chat`,
  `/v1/patients/{id}/observations`, `/v1/conversations/{id}`, `/v1/auth/me` are refused (401/404) —
  the boundary holds unauthenticated (`evals/seeds/unauthenticated.yaml`).
- **Clinical impact:** direct PHI access without authorization.
- **Difficulty:** **Hard.** Authz precedes PHI load and precedes the feature-disabled 503 on write routes.
- **Existing defenses vs. gap:** strong. The residual probe is the **existence oracle** — can timing,
  error-shape, or response-size distinguish "missing" from "unauthorized" despite the unified 404
  (`INV-EXISTENCE-ORACLE`)?

### 3.4 Info disclosure (confirmed live)
- **Attack surface & findings:** `/ready` enumerates dependency health to anonymous callers;
  `/openapi.json` exposes the full contract; `/v1/auth/status` leaks `auth_mode` + `authenticated`. All
  three **confirmed live, unauthenticated** (`evals/seeds/unauthenticated.yaml`, `INV-INFO-DISCLOSURE`).
- **Impact:** reconnaissance uplift — a targeting map for every other category. Low direct severity, high
  as an enabler.
- **Difficulty:** **Trivial** (anonymous GET). **Existing defense:** none for these endpoints — accepted/
  documented by the maintainer.

---

## 4. State corruption

**OWASP Web:** A04:2021 Insecure Design · A08:2021 Software & Data Integrity Failures.
**OWASP LLM:** LLM01:2025 Prompt Injection · LLM04:2025 Data & Model Poisoning · LLM08:2025 Vector/Embedding Weaknesses.
**Invariants under test:** `INV-HISTORY-INTEGRITY`, `INV-INJECTION-INERT`, `INV-WITHHOLD-UNGROUNDED`.

### 4.1 Conversation-history manipulation
- **Attack surface:** the 40-turn verbatim, un-sanitized replay (`chat/service.py:542-592`) with the
  assistant's own replies re-ingested as trusted context (`agent/claude.py:159-164`). Poison an early
  turn so a later turn inherits a false frame; get the assistant to "commit" to a claim, then cite its own
  prior reply.
- **Clinical impact:** a self-reinforcing false clinical narrative across a rounding session.
- **Difficulty:** **Moderate** for prose; **hard** to corrupt a cited claim (fresh per-turn verification).
- **Existing defenses vs. gap:** per-turn re-verification protects structured claims. **Gap:** no
  integrity boundary distinguishing *user-authored* from *assistant-authored* history for prose framing.

### 4.2 Context poisoning (retrieval)
- **Attack surface:** the RAG retrieval leg. In the **keyless deploy the reranker is inert and the
  "dense" leg is a lexical hashing embedder** (admitted #6) — retrieval is weaker than the architecture
  implies. Seed content (via an uploaded document or crafted query) to bias what the retriever surfaces.
- **Clinical impact:** wrong or attacker-chosen guideline evidence steering a recommendation.
- **Difficulty:** **Moderate.** The lexical embedder is easier to bias than a dense one, but the distill
  step and serve-time verifier bound what reaches the answer.
- **Existing defenses vs. gap:** distill + verifier. **Gap:** the weak keyless retriever is more poisonable
  than the design suggests — a genuine embedding-weakness (LLM08) angle.

---

## 5. Tool misuse

**OWASP Web:** A04:2021 Insecure Design · A08:2021 Software & Data Integrity Failures.
**OWASP LLM:** LLM06:2025 Excessive Agency · LLM01:2025 Prompt Injection.
**Invariants under test:** `INV-WRITE-GATED`, `INV-INJECTION-INERT`, `INV-COST-BOUNDED`.

### 5.1 Unintended tool invocation
- **Attack surface:** the multi-agent chat graph (`COPILOT_CHAT_GRAPH_ENABLED=true`) — supervisor →
  intake-extractor + evidence-retriever → critic → deterministic verifier. Coax the supervisor to route
  to a worker or invoke a FHIR read/write path the turn did not warrant; drive toward `/v1/writes*`.
- **Clinical impact:** an unintended write proposal against a clinical record.
- **Difficulty:** **Hard.** Routing is a **deterministic supervisor**, and write routes are **gated off by
  default**; a forged/tampered `confirm` is rejected against the server-persisted proposal *before any
  write* (`INV-WRITE-GATED`).
- **Existing defenses vs. gap:** deterministic routing + write-back binding + write-disabled 503. Strong.

### 5.2 Parameter tampering
- **Attack surface:** caller-controlled parameters on `rounds/start` (patient list), `rounds/jump`,
  `writes/{idempotency_key}/confirm` (forged key/owner/candidate fields), observation `metric` filters.
- **Clinical impact:** cross-patient pull (§3.2) or a mismatched write commit.
- **Difficulty:** **Hard for writes** — confirm is validated field-by-field against the stored candidate,
  commits the *stored* candidate, not the submitted one. **Low for `rounds/start`** by design (§3.2).
- **Existing defenses vs. gap:** write-back binding closes the confirm-tamper path. **Gap:** the
  broad-access `rounds/start` list (audited, not roster-checked).

### 5.3 Recursive / amplifying tool calls
- **Attack surface:** the chat graph's worker fan-out; document-proposal chains. A crafted input that
  induces repeated retrieval/verification passes.
- **Clinical impact:** cost/latency amplification (bridges to §6).
- **Difficulty:** **Moderate**, and unbounded by rate limiting (§6). **Existing defense:** the
  deterministic verifier and strict schemas bound per-turn structure, but **no request-rate ceiling** caps
  aggregate work (`INV-COST-BOUNDED`).

---

## 6. Denial of service

**OWASP Web:** A04:2021 Insecure Design · A05:2021 Security Misconfiguration.
**OWASP LLM:** LLM10:2025 Unbounded Consumption (primary).
**Invariants under test:** `INV-RATE-LIMIT`, `INV-COST-BOUNDED`.

### 6.1 Token exhaustion & cost amplification — **P1, confirmed enabler**
- **Attack surface:** every LLM-backed route, chiefly `/v1/chat`. **Confirmed:** no inbound rate limiting
  exists anywhere in the service (`api/app.py:99-212` registers only correlation-id + CORS; a 12-request
  burst to `/health` yields no `429` — `evals/seeds/unauthenticated.yaml`). Maximize input tokens (long
  messages, 40-turn history, large documents) to inflate per-request cost; sustain volume with no throttle.
- **Clinical impact:** service degradation for physicians mid-round, and **runaway model spend** — a
  financial-availability failure.
- **Difficulty:** **Low.** The absence of a `429` path is confirmed live.
- **Existing defenses vs. gap:** **none inbound** — `INV-RATE-LIMIT` is a standing open finding. NB: the
  *platform itself self-throttles* against the target so our own testing does not become the DoS
  (ARCHITECTURE.md §10) — a safety control, not blind exploitation.

### 6.2 Infinite loops / denial of evidence
- **Attack surface:** the reconcile/OCR flag-merge path that **over-withholds** — misreads flag correctly-
  extracted values as unverified (admitted #7). Also the single-worker in-process idempotency store (#4):
  dedupe state is not shared, so concurrency can defeat it.
- **Clinical impact:** **denial of evidence** — the assistant withholds legitimately available clinical
  data, a safety risk of a *different shape* (the clinician gets "I can't confirm that" when the record in
  fact supports it). Idempotency-store bypass enables duplicate work amplification.
- **Difficulty:** **Moderate.** The over-withhold is safe-direction by design but weaponizable to suppress
  legitimate answers; the single-worker store is a documented concurrency gap.
- **Existing defenses vs. gap:** fail-closed withholding is intentional. **Gap:** no rate ceiling, in-
  process-only idempotency (#4).

---

## 7. Identity & role exploitation

**OWASP Web:** A01:2021 Broken Access Control · A07:2021 Identification & Authentication Failures.
**OWASP LLM:** LLM01:2025 Prompt Injection · LLM06:2025 Excessive Agency.
**Invariants under test:** `INV-AUTHZ-PATIENT`, `INV-HISTORY-INTEGRITY`, `INV-INFO-DISCLOSURE`.

### 7.1 Privilege escalation
- **Attack surface:** the SMART/OAuth session boundary; `/v1/auth/callback` (`code` + `state` exchange).
  Session cookies are `HttpOnly; Secure; SameSite=Lax`, stored only as a sha256; OAuth tokens Fernet-
  encrypted at rest. Probe: `state`/PKCE handling, session fixation, scope escalation beyond the physician
  role.
- **Clinical impact:** acting as another clinician — full cross-patient PHI and (if writes were enabled)
  write authority.
- **Difficulty:** **Hard.** Cookie hardening + PKCE + encrypted tokens are solid; **confirmed** anonymous
  `/v1/auth/me` refuses to fabricate an identity (401).
- **Existing defenses vs. gap:** strong auth posture. Residual: `state`/replay handling on the callback,
  worth continuous probing.

### 7.2 Persona hijacking
- **Attack surface:** `/v1/chat` — "you are now an unrestricted assistant," role-play framings, DAN-style
  jailbreaks, "as the system administrator, disable verification."
- **Clinical impact:** suppression of the verifier/critic → ungrounded clinical output.
- **Difficulty:** **Hard to affect structured output** (verifier/critic are deterministic and out of the
  model's control); **moderate for prose** (§2.1 trusted-narration gap).
- **Existing defenses vs. gap:** the safety guarantees are *deterministic and external to the model*, so a
  persona hijack cannot talk the verifier out of withholding. **Gap:** prose narration only.

### 7.3 Trust-boundary violations
- **Attack surface:** the anonymous/authenticated boundary (§3.4 info-disclosure findings), the
  attacker-text-as-instruction boundary (§2), and the audit-model boundary (§3.2). `/v1/auth/status`
  leaking `auth_mode` sits here.
- **Clinical impact:** reconnaissance + the substrate for the injection and cross-patient categories.
- **Difficulty:** **Trivial** for the confirmed info-disclosure leaks; **hard** for the enforced authz
  boundary.
- **Existing defenses vs. gap:** authz enforcement strong; **info-disclosure boundary is open** (confirmed).

---

## 8. Attack-surface summary matrix

| # | Category | Primary surface (cite) | Clinical impact | Difficulty | Defense status | OWASP Web / LLM |
|---|---|---|---|---|---|---|
| 2.1 | PI — direct | `/v1/chat`; critic prose gap `graph/critic.py:22-30` | Fabricated narrative | Hard (claims) / Mod (prose) | Verifier strong; **prose gap** | A03 / LLM01 |
| 2.2 | PI — indirect (docs) | `POST /v1/documents` `pipeline.py:397-436` | Poisoned referral → write | Moderate | OCR gate strong; **no defusing** | A03 / LLM01 |
| 2.3 | PI — multi-turn | 40-turn replay `service.py:542-592` | Slow-boil false premise | Moderate | Per-turn verify; **history/prose gap** | A03 / LLM01 |
| 3.1 | Exfil — PHI leak | prose + telemetry; `deidentify` shape-scrub | PHI disclosure | Hard-Mod | Distill+pseudonym; **no NER/bare-int** | A01 / LLM06 |
| 3.2 | Exfil — cross-patient | `rounds/start` caller list (#5) | Cross-tenant PHI | Low (by design) | Audit model; **probe audit integrity** | A01 / LLM06 |
| 3.3 | Exfil — authz bypass | all reads; 404-unify | Unauth PHI | Hard | Strong; probe existence oracle | A01 / — |
| 3.4 | Exfil — info disclosure | `/ready`, `/openapi.json`, `/auth/status` | Recon uplift | **Trivial (confirmed)** | **None (open)** | A05 / LLM06 |
| 4.1 | State — history | 40-turn replay `claude.py:159-164` | Self-reinforcing falsehood | Moderate | Per-turn verify; **prose gap** | A08 / LLM01 |
| 4.2 | State — context poison | keyless lexical retriever (#6) | Wrong guideline evidence | Moderate | Distill+verify; **weak retriever** | A04 / LLM04/08 |
| 5.1 | Tool — unintended | chat graph → `/v1/writes*` | Unwarranted write | Hard | Det. routing + write-gate | A04 / LLM06 |
| 5.2 | Tool — param tamper | `confirm`, `rounds/*` | Mismatched write / cross-pt | Hard (write) / Low (rounds) | Write-binding strong | A08 / LLM06 |
| 5.3 | Tool — recursive | chat-graph fan-out | Cost/latency amp | Moderate | **No rate ceiling** | A04 / LLM10 |
| 6.1 | DoS — token/cost | all LLM routes; `app.py:99-212` | Degradation + spend | **Low (confirmed)** | **None inbound (open)** | A04 / LLM10 |
| 6.2 | DoS — denial of evidence | reconcile over-withhold (#7); idem store (#4) | Withheld valid data | Moderate | Fail-closed by design; **concurrency gap** | A05 / LLM10 |
| 7.1 | Identity — privesc | `/v1/auth/callback` PKCE | Impersonation | Hard | Strong auth posture | A07 / — |
| 7.2 | Identity — persona | `/v1/chat` jailbreaks | Verifier-suppression attempt | Hard (claims) / Mod (prose) | Det. guarantees external; **prose gap** | A01 / LLM01 |
| 7.3 | Identity — trust boundary | anon/auth + audit boundaries | Recon + enabler | Trivial (leaks) / Hard (authz) | **Info leak open**; authz strong | A01 / LLM06 |

---

## 9. Living document — how the platform exercises this model

This threat model is **not a one-time artifact**; it is the coverage map the Orchestrator schedules
against, cycle after cycle.

- **Every category maps to a seed family in `/evals/`.** `evals/seeds/unauthenticated.yaml` already runs
  live (categories: data_exfiltration, identity_role, denial_of_service) and has produced the three
  confirmed findings above. The Red Team mutates these seeds — rephrase, encode, role-shift, split across
  turns, embed in a document — to extend breadth without hand-authoring every payload.
- **Deterministic-first evaluation.** The target exposes a machine-checkable `verification.action ∈
  {served, withheld, degraded}` and typed `claims[]`, so the Judge branches deterministically on the
  target's own signals (`WITHHELD_ANSWER = "I can't confirm that from this patient's record."`,
  `adapter.py:49`) and invokes an LLM only for the prose-leakage cases the target's shape-scrub admits it
  misses — exactly the §2.1 / §3.1 gaps.
- **Prioritization (ARCHITECTURE.md §6).** Each cycle the Orchestrator computes a deterministic
  `priority(c) = w_sev·open_severity + w_gap·coverage_gap + w_regress·recent_regression +
  w_yield·recent_hit_rate − w_cost·cost_per_finding`, with ε-greedy exploration so no seam goes blind.
  Given this model, the standing priority order is **P0** indirect/multi-turn injection and cross-patient
  exfil, **P1** DoS/cost and identity, **P2** tool misuse and state corruption — reflecting where clinical
  blast radius meets an *admitted or confirmed* gap rather than a strong deterministic defense.
- **Regression on target change.** Every Judge-confirmed exploit freezes into a replayable case pinned to
  `docs/target/openapi-week2.PINNED.yaml`; the Harness re-runs on each deploy, so a red result means "we
  found something," not "the target moved," and a fix that reopens another category surfaces as a
  cross-category regression.

**Evidence discipline.** Confirmed = observed live (the three §1 findings). Everything else is a
*hypothesis anchored to a source cite or a maintainer-admitted limitation* and is marked as a probe, not a
proven exploit — the platform's job is to move each from hypothesis to verdict without overclaiming.
