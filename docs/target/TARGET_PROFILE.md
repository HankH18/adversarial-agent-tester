# Target Profile — AgentForge Clinical Co-Pilot (system under test)

> **Supporting context, not a deliverable.** The project doc (`docs/Week_3_AgentForge.pdf`) defines
> what `THREAT_MODEL.md` must contain — attack surface, impact, exploit difficulty, existing-defense
> coverage, and a ~500-word summary. This file is raw material for that analysis: what the target
> *is*, what it *claims*, and what it *admits*. The analysis and prioritization are yours.
>
> Every claim below is traceable to the target repo (`../openemr-base-clean`) — verify before relying
> on it; the target moves.

## What it is

An AI clinical assistant ("Clinical Co-Pilot") for hospitalists, built on an OpenEMR fork. It reads
and writes patient data **only** through OpenEMR's FHIR/REST API. A Python/FastAPI service (`agent/`)
holds the agent; OpenEMR remains the system of record. Demo data is synthetic.

- **Live target:** https://agentforge.hankholcomb.com (authorized — user-owned)
- **Auth posture:** `auth_mode=smart` — per-physician SMART/OAuth login against OpenEMR. Session
  cookies are `HttpOnly; Secure; SameSite=Lax`; the cookie value is stored only as a sha256; OAuth
  tokens are Fernet-encrypted at rest.
- **Multi-agent chat is ON in the deploy** (`COPILOT_CHAT_GRAPH_ENABLED=true`): a deterministic
  supervisor routes to an intake-extractor and an evidence-retriever worker, then a critic, then a
  deterministic verifier.

## Attack surface — 24 published endpoints

Frozen copy: `openapi-week2.PINNED.yaml`. Grouped by what an attacker would care about:

| Group | Endpoints | Notes |
|---|---|---|
| **Unauthenticated / infra** | `/health`, `/ready`, `/status`, `/openapi.json` | `/ready` is anonymous-public and enumerates dependency health |
| **Auth** | `/v1/auth/login`, `/callback`, `/logout`, `/me`, `/status` | OAuth callback takes `code` + `state` |
| **Chat (LLM surface)** | `/v1/chat`, `/v1/conversations/{id}` | Primary prompt-injection + multi-turn surface |
| **Documents (upload surface)** | `POST /v1/documents`, `GET /v1/documents/{id}`, `/pages/{n}` | Indirect-injection via uploaded content; page images |
| **Rounds / patient data** | `/v1/rounds/start`, `/current`, `/advance`, `/jump`, `/refresh`, `/alerts` | `rounds/start` takes a caller-supplied patient list |
| **Observations** | `/v1/patients/{patient_id}/observations` | Direct patient-scoped read |
| **Write-back** | `/v1/writes`, `/writes/propose-from-document/{id}`, `/writes/{idempotency_key}/confirm` | Propose→confirm; gated off by default |

## Existing defenses (the claims worth trying to falsify)

- **Fail-closed serve-time verification** — `verification/serve.py` re-fetches every cited FHIR
  resource **live** and re-checks it; an unverifiable claim is dropped; if nothing survives the whole
  turn is withheld. Binary, not a confidence threshold.
- **No-invention OCR gate** — an extracted document value is `supported` only if it is located in that
  page's OCR tokens (two-sided coverage + similarity + a legibility floor); otherwise no bbox, no
  citation. Deliberately over-withholds.
- **Authorization** — patient access is checked against the clinician's rounding list *before* any PHI
  is loaded; document and conversation reads unify "missing" and "unauthorized" on the **same 404** to
  avoid an existence oracle; write routes check authz *before* the feature-disabled 503.
- **PHI egress control** — `rag/deidentify.py` shape-scrubs identifiers, then a *distill* step drops
  any token not in the guideline vocabulary before anything reaches a remote embedder/reranker.
- **Telemetry pseudonymization** — `patient_id` is HMAC-pseudonymized at the single Langfuse egress,
  and **dropped fail-closed** if the pseudonym key is unset.
- **Write-back binding** — `confirm` is validated against the **server-persisted** proposal (key,
  owner, and every candidate field) and commits the *stored* candidate, so a forged/tampered confirm
  is rejected before any write.
- **Critic** — rejects uncited claims deterministically; the keyed LLM pass is demote-only and
  fail-closed (unknown reason → treated as unsafe → whole-turn withhold).
- **Strict schemas** — extraction models are `strict=True, extra="forbid", frozen=True`; raw model
  output is always re-validated.
- **Audit trail** — every PHI read appends to an append-only `audit_log` with a correlation id.
- **Eval hard gate** — 62 deterministic cases across 5 boolean rubrics, PR-blocking.

## The target's own documented limitations (highest-yield starting points)

From `WALKTHROUGH.md §6` and `agent/research/week3/` in the target repo — the maintainer disclosed
these; an adversary would start here:

1. **`deidentify` is a shape-scrub, not NER** — a bare, unlabelled name in free text is not matched by
   the regex. Bounded by the distill step, but the gap is real and admitted.
2. **Prose is trusted narration** — the critic screens the structured claim *chips*, not the free-text
   answer body. A withheld/demoted claim is protected by a whole-turn withhold, not a sentence-level
   screen. (Explicitly deferred as "Week-3 scope.")
3. **`phi_check` has no bare-integer detector** — an unpseudonymized numeric `patient_id` reaching
   telemetry would not be caught by the free-text PHI scan.
4. **Single-worker idempotency store** — dedupe/idempotency state is in-process, not shared.
5. **Broad-access-plus-audit is a deliberate model** — `rounds/start` accepts a caller-supplied patient
   list with no per-patient roster check; the token grants all patients and every read is audited. The
   maintainer has *accepted* this rather than treating it as a defect. Worth probing whether the audit
   trail actually holds under abuse.
6. **Keyless deploy** — the reranker is inert and the "dense" retrieval leg is a lexical hashing
   embedder, so retrieval is weaker than the architecture implies (relevant to context-poisoning).
7. **Reconcile over-withholds** — OCR flag-merge and misreads cause correctly-extracted values to be
   flagged unverified (safe direction, but a denial-of-evidence angle).
8. **No scheduled backups**; **stale frozen acceptance test** (`test_api_02` still encodes a pre-fix
   unauthenticated-read contract).

## What the target already tests (aim at the gaps)

- `.swarm-loop/acceptance/` — a frozen, cross-cutting acceptance suite (~46 criteria).
- `agent/evals/` — the 62-case eval gate, incl. 9 "live" cases that exercise real code.
- A PHI-scan CI job over a generated corpus covering the chat egress **and** five lifecycle event
  families.

Two adversarial passes have already been run against this codebase and its findings fixed, so
low-hanging correctness bugs are largely gone. The interesting surface is behavioral and adversarial:
injection, multi-turn state, indirect content, authorization edges, and cost/DoS.
