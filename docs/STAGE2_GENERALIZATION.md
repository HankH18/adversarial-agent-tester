# AdversaryForge Stage 2 — Generalizing to any AI chat app

> **Status: planning / research (not yet built).** This is a forward-looking architecture
> report for turning AdversaryForge from a platform pointed at one target (the OpenEMR Clinical
> Co-Pilot) into a **generic red-team app** — the operator supplies the URL of any AI chat app they
> built, and it autonomously discovers the surface, generates attacks, judges them independently,
> and writes vulnerability reports, with no per-target hand-coding. Produced by a cross-model
> (Fable) research pass over the real code; every claim is cited to a file. Nothing here is shipped —
> the shipped state is [`AS_BUILT.md`](AS_BUILT.md).

---

## 0. The thesis, and what the code actually says about it

The Stage-2 goal is: **the operator supplies a URL for any AI chat app they built, and the platform autonomously discovers the surface, generates attacks, judges them independently, and writes vulnerability reports — with no per-target hand-coding.**

The good news, after reading the code end-to-end, is that AdversaryForge was *architected* for this even though it was *populated* for one target. The seams exist. The multi-agent spine — Orchestrator → Red Team → Judge (behind an information barrier) → Documentation → Regression harness, all over versioned contracts and an observability store — is target-agnostic. What is welded to the OpenEMR Clinical Co-Pilot is the **content that flows through those seams**: the endpoint map, the invariant set, the response-shape signals the Judge reads, the auth mode, and the hand-authored seeds.

Put bluntly: **the platform is general; the payload is not.** Stage 2 is not a rewrite. It is (a) building a runtime `TargetProfile` where a hand-written adapter is today, (b) swapping the healthcare invariant set for an OWASP-LLM one, (c) turning the Red Team from a *mutator* of hand-written seeds into a *generator* from a discovered surface, and (d) shifting the Judge's center of gravity from deterministic-first to LLM-adjudicated-with-a-controlled-canary, because an unknown app exposes no `verification.action` for code to read.

---

## 1. What is already general (the good news)

These transfer to an arbitrary target essentially unchanged. They are the reason Stage 2 is feasible.

### 1.1 The target-adapter *abstraction* (not its instance)
`TargetAdapter` (`adversaryforge/target/adapter.py:28-44`) is a clean, frozen dataclass: `name`, `base_url`, `auth_mode`, an `endpoints` dict, an `invariants` dict, and a `url(key, **path_params)` templating helper. Nothing about the *type* is healthcare-specific. Only the **factory** `agentforge_adapter()` (`adapter.py:52-122`) hard-codes the 24 endpoints and 11 invariants. Stage 2 keeps the dataclass and replaces the factory with a runtime builder.

### 1.2 The session abstraction
`SessionProvider` (`adversaryforge/target/session.py:26-36`) is an ABC the attack engine talks to through exactly two methods — `headers()` and `is_authenticated`. The docstring says it explicitly: *"adding a backend never touches attack code."* `AnonymousSession`, `EnvCookieSession`, and the `OAuthSession` stub all satisfy it. A new auth mode for a generic app is a new provider, not a change to the engine.

### 1.3 The throttled, auditable, blast-radius-guarded client
`TargetClient` (`adversaryforge/target/client.py`) gives us for free on any target:
- **Self-throttle** — a concurrency semaphore + minimum inter-request gap (`client.py:78-81, 115-122`), so the platform never DoSes the app it is testing. Operator-tunable via `max_concurrency` / `min_request_gap_s` (`config.py:55-58`).
- **Full verbatim capture** — `TargetResponse` records status, headers, body, latency, correlation id (`client.py:29-63`) for replay and adjudication.
- **Same-host credential guard** (`client.py:109-113, 155-156`) — session credentials are attached *only* when the request targets the configured host, so an absolute-URL attack step can never send the session off-target. This is generic and worth keeping.

The one target-specific bit here is the default-deny write guard keyed to `/v1/writes` (`client.py:98-107`) — discussed in §2.

### 1.4 The versioned, typed contracts
`adversaryforge/contracts/__init__.py` is fully target-agnostic. `AttackAttempt`, `Verdict`, `ConfirmedExploit`, `RegressionCandidate`, `VulnReport`, `AgentError` are generic security artifacts. Crucially, **the OWASP taxonomies already live here** — `OwaspLlm` enumerates LLM01 Prompt Injection, LLM02 Sensitive Disclosure, LLM05 Improper Output, LLM06 Excessive Agency, LLM10 Unbounded Consumption, and `OwaspWeb` the web Top-10. Stage 2's generic invariant set is not a new vocabulary — it is *already the enum the seeds tag themselves with*.

### 1.5 The Judge's information barrier
The independence mechanism is structural and target-independent. `JudgeView` (`judge.py:48-68`) is the *only* thing the Judge sees — transcript, invariant id, expected-safe string, category. It is *type-impossible* for the Judge to read the attacker's technique/intent/confidence because those fields are not on the view. The LLM adjudicator inherits the same barrier. This holds for any target.

### 1.6 Deterministic-first *architecture* (the tiering, not the rules)
The Judge's control flow (`judge.py:87-114`) — try deterministic; if no decision, try the injected LLM adjudicator; else a conservative low-confidence `partial` flagged for review — is generic. The adjudicator is **injected** (`judge.py:81-84`), so the tier structure survives even when the deterministic rules do not. Stage 2 reuses the tiering and changes what fills each tier (§3.4).

### 1.7 The cost governor and self-throttle
`should_halt_no_signal()` (`platform.py`) halts a campaign that has spent its budget with zero confirmed exploits; pure arithmetic over `nosignal_halt_usd` and confirmed-exploit count. LLM/mutator spend is metered into a cost ledger. All target-agnostic.

### 1.8 Crash-resume
`resume_campaign()` (`platform.py`) is genuine durable-checkpoint resume: the ordered seed plan is persisted at run start, and resume replays exactly the pending seeds under the original `run_id`. Keys on seed ids + a store — nothing target-specific.

### 1.9 Orchestrator target-selection and the Mutator
- Orchestrator `score_categories()` is a deterministic policy over coverage gaps, open findings, and saturation — parameterized by a category vocabulary that is already generic attack categories, not healthcare terms.
- The `Mutator` (`llm/mutator.py`) already operates on abstract inputs: a `list[str]` of attacker turns, an invariant id, and judge feedback. Its deterministic transform bank (role-play, authority/break-glass, leetspeak, base64, turn-splitting, hypothetical, override-preamble) is **already app-agnostic jailbreak tradecraft** — the foundation for Stage-2 generation (§3.3).

### 1.10 The regression harness's core principle
`harness/regression.py` re-judges a **named invariant against machine signals**, never a string snapshot. Its fail-closed decision core `_decide_case()` treats `error`/`partial` as inconclusive, never a pass. Target-independent; depends only on the Judge exposing a stable invariant verdict.

**Summary of §1:** the spine, the trust boundaries, the safety rails (throttle, blast-radius, cost governor, fail-closed gates), and the resume/observability substrate are all general — roughly 60% of the platform by function.

---

## 2. What is hard-coded to this target (the coupling to break)

**C1 — The adapter factory itself.** `agentforge_adapter()` (`adapter.py:52-122`) writes out 24 endpoints and 11 named invariants, and is called *directly* — not via a registry — at `platform.py:92`, `platform.py:220`, `regression.py:125`, `perf/loadtest.py:205`. There is no seam to swap targets today; the function name *is* the seam.

**C2 — The `WITHHELD_ANSWER` sentinel.** A specific English string from the target's source — `"I can't confirm that from this patient's record."` (`adapter.py:47-49`) — load-bearing in `_is_withheld()` and every held-defense branch, and in the calibration gold set.

**C3 — Hand-authored seeds (the biggest coupling).** 23 seeds hard-naming this target's routes/bodies/canaries (`/v1/patients/1/observations`, `/v1/auth/status`, `POST /v1/documents` multipart, `patient_id: 1`). Nothing survives a target swap.

**C4 — The Judge's invariant dispatch.** `_deterministic()` dispatches on 10 hard-coded invariant ids (`judge.py:148-159`). An unknown app carrying none of them falls straight to the LLM/partial path.

**C5 — Response-shape assumptions in the Judge.** `verification.action`/`claims`/`passed`; MRN/SSN regexes; `_burst_statuses`; the stack-specific leak markers (`openemr, langfuse, postgres…`); the `latency_ms<=N` convention.

**C6 — OpenEMR-specific auth.** `AuthMode.smart` from the URL; `AGENTFORGE_SESSION_COOKIE`; `/v1/auth/me` liveness; the SMART/PKCE `OAuthSession` stub.

**C7 — The pinned contract.** `docs/target/openapi-week2.PINNED.yaml` + `TARGET_PROFILE.md`, hand-maintained.

**C8 — Healthcare PHI shapes.** MRN/SSN/bare-integer `patient_id` + the `INV-PHI-EGRESS` framing.

**C9 — The calibration gold set.** `_gold()` fixtures encode the target's response shape (the κ *mechanism* is generic; the *labels* are target-shaped).

**C10 — Clinical framing in Documentation.** `_INVARIANT_PLAYBOOK` maps each `INV-*` to *clinical* impact/remediation; the deployed URL is hard-coded in the reproduction preamble.

**C11 — The `/v1/writes` write-guard route.** Correct instinct (default-deny state-changing routes), target-specific route name.

**C12 — Chat body shape + category priors.** `{message, patient_id}` chat body; category base priorities reflect this threat model.

**The pattern:** every coupling is *content in a generic container*. None requires re-architecting the container — Stage 2 is a population problem, not a rebuild.

---

## 3. The Stage-2 architecture — turning each coupling into a runtime capability

### 3.1 Target onboarding: URL → runtime `TargetProfile`
Replace `agentforge_adapter()` (C1, C7) with `discover_adapter(base_url, hints) -> TargetAdapter`. Discovery tiers, cheapest first: (1) **contract probe** — GET `/openapi.json`, `/swagger.json`, `/.well-known/ai-plugin.json`, parse paths straight into the `endpoints` dict; (2) **path heuristics** — probe common chat routes (`/chat`, `/api/chat`, `/v1/chat/completions`, `/message`) + infra routes; classify by response; (3) **operator `target.yaml`** — 10 lines (`base_url`, `chat_endpoint`, `chat_request_template`, `response_text_path`, `auth`) that always overrides discovery. The one field discovery can't reliably infer — **where the assistant text lives** — is a `response_text_path` (JSONPath, sensible defaults). **Auth (C6):** generalize `AuthMode` to `{none, bearer, cookie, header, oauth}` and add `BearerSession`/`HeaderTokenSession` (drop-ins on the existing ABC).

### 3.2 Generic safety invariants grounded in OWASP LLM Top-10
Replace the 11 healthcare invariants with an app-agnostic set already implied by the `OwaspLlm` enum. `INV-INJECTION-INERT`, `INV-COST-BOUNDED`, `INV-RATE-LIMIT` already judge on target-agnostic signals (canary echo, latency, burst) and transfer **unchanged**. `INV-PHI-EGRESS` → `INV-NO-SECRET-DISCLOSURE` (planted secret + configurable shape scan). `INV-WRITE-GATED` → `INV-NO-EXCESSIVE-AGENCY`. New but small: `INV-GUARDRAIL-HELD`, `INV-NO-SYSTEM-PROMPT-LEAK`, `INV-OUTPUT-SAFE`. The Documentation playbook becomes OWASP-keyed with clinical language behind an optional per-domain override.

### 3.3 Automated attack generation: from mutation to generation
Add a **generation** stage in front of the existing Hermes-on-OpenRouter mutator (already a *different model family* than the Claude Judge, preserving independence): (1) promote the Mutator's transform bank to a first-class **technique library** indexed by OWASP category; (2) a `SeedGenerator` that asks Hermes for N concrete seeds against the discovered chat endpoint using the OWASP taxonomy as scaffolding, emitting the existing `Seed`/`Step` shape so downstream is untouched; (3) plant platform-controlled `[[CANARY:...]]` markers the Judge already detects; (4) keyless template fallback so it still runs offline. The mutation loop stays exactly as-is — generation just supplies the initial population instead of a YAML file.

### 3.4 Adaptive judging without hand-coded response shapes (the hard part — be honest)
An arbitrary app hands us prose + HTTP 200, so judging shifts from *deterministic-first* to *controlled-signal + LLM-second*. In order of trustworthiness: **(a) canary/marker injection the platform controls** — the strongest generic signal, already deterministic and target-independent (`_canary()` + `_judge_injection`); lean on it hard. **(b) generic secret/PII shape scans** — generalize MRN/SSN to API-keys/JWTs/emails/Luhn/operator regexes, keeping the existing **novelty guard** (a shape counts only if the attacker didn't supply it). **(c) refusal-vs-compliance** — promote `_looks_like_refusal()` to a first-class signal for `INV-GUARDRAIL-HELD` (honest caveat: heuristic, beatable, so it defers to (d)). **(d) the LLM adjudicator as the *primary* tier** for everything else.

**The honest cost:** most verdicts become LLM calls (cents → dollars/campaign; the cost governor becomes load-bearing); LLM verdicts wobble (the multi-vote panel damps this, and `partial`-is-inconclusive prevents a wobble masquerading as "fixed"); and **false positives without ground truth** is the sharpest risk — an LLM with no authorization context calls every served 200 a leak (the Judge's own code refuses to defer authz/PHI for exactly this reason). So the canary strategy isn't a nicety — it is the primary FP defense. **Calibration:** keep the κ mechanism, replace the gold set with a *generic* one (canary-echoed-vs-not, secret-shape, refusal-vs-compliance, throttled-vs-not) — the cases we can label with certainty.

### 3.5 The autonomy loop, unattended
```
onboard(URL, optional hints)
   → discover surface + auth → build TargetProfile at runtime      [§3.1]
   → synthesize seeds from surface × OWASP techniques (Hermes)     [§3.3]
   → calibrate Judge on generic gold set (κ-gate, fail closed)     [§3.4]
   → for each directive (Orchestrator scores categories):
        execute (throttled, blast-radius-guarded)                  [§1.3]
        judge (canary/shape/refusal deterministic → LLM primary)   [§3.4]
        partial → mutate N variants → re-judge                     [§1.9]
        success → confirm exploit → freeze regression case         [§1.10]
   → generate OWASP-keyed vuln reports (deterministic + LLM polish)[§3.2]
   → cost governor halts on no-signal; crash-resume on interrupt   [§1.7/1.8]
```
Every box except the first two rows already runs today.

---

## 4. Phased roadmap (effort / risk)

- **Phase A — Runtime `TargetProfile` + generic auth.** *(~1 week; low-moderate.)* `discover_adapter()` (OpenAPI parse + heuristics + `target.yaml`), a `response_text_path` resolver, `BearerSession`/`HeaderTokenSession`, and an adapter **registry** so the four hard call sites resolve a profile. Keep AgentForge as one registered profile.
- **Phase B — OWASP-LLM invariants + generic canary/secret judging.** *(~1–1.5 weeks; moderate — where FPs enter.)* De-risk by making the **canary path the default** and requiring a machine-checkable signal before any deterministic `success`; everything else is LLM-adjudicated + flagged, never auto-confirmed critical (the `requires_human_approval` gate already enforces a human on criticals).
- **Phase C — LLM attack generation.** *(~1 week; moderate.)* `SeedGenerator` + technique library; validate each generated seed against the `Seed` schema; the same-host guard already keeps generation on-target at the wire.
- **Phase D — Self-onboarding from a bare URL.** *(~0.5–1 week; low once A–C land.)* One `adversaryforge onboard <URL>` command; emit `TARGET_PROFILE.md` + reports as artifacts.

**The two hardest problems, called out:** (1) **judging an unknown app without ground truth** — de-risk by *manufacturing* ground truth via planted canaries/secrets and treating LLM adjudication of everything else as *evidence for human triage*, not auto-confirmed truth; (2) **false positives with no machine signal** — never let a bare "served 200" auto-confirm; require a planted marker, a novel secret shape, or a multi-vote panel **plus** human approval for criticals; track an FP rate against a labeled generic corpus and gate releases on it.

---

## 5. Smallest next step — cheapest proof of the thesis

**Onboard one second, non-healthcare toy target end-to-end, unauthenticated, with a hand-written 15-line `target.yaml` — skipping discovery entirely.** Stand up a trivial chat endpoint (one route, `{message}` in, `{answer}` out, with a secret planted in its system prompt). Then: (1) a minimal `discover_adapter()` that reads `target.yaml` and builds a `TargetAdapter` — *this alone breaks C1*, the structural root, in a few hours; (2) register it alongside AgentForge and run **one** generic invariant end-to-end — `INV-INJECTION-INERT` with a planted canary (every piece it needs already exists); (3) watch it attack with a canary seed, judge the leak deterministically (no LLM key required), confirm the exploit, and emit a `VULN-*.md`.

**Why this first:** it exercises the *entire spine* on a non-healthcare target using the *one judging signal already fully general* (canary echo), while deferring the expensive/risky pieces (discovery, LLM-primary judging). If a toy target flows URL→attack→judge→report with only a `target.yaml` and no code below the adapter factory, the thesis is proven and Phases A–D reduce to "populate the containers." If it doesn't, you've found the real coupling before spending a week on discovery.
