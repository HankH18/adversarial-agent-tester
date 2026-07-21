# Build-vs-Configure Decision Record

> **Required Architecture Defense deliverable** (case study, p.11: *"Before implementing any agent role,
> document a build-versus-configure decision record: what existing tools were evaluated (Burp Suite,
> OWASP ZAP, Semgrep, Garak, commercial red-team platforms), what each covers, where it falls short for
> this use case, and why a custom agent is justified over configuring an existing tool."*)
>
> **This is an evidence record, not an opinion.** Every capability, price, and limitation below is
> attributed to a primary source (vendor docs, GitHub source, standards PDFs, arXiv). The
> tool-comparison claims (§4) were run through **adversarial 3-vote verification** (a claim survived
> only if it could not be refuted 2-of-3); those verdicts are marked **[verified 3-0]**. Supporting
> evidence (vendors, methodology anchors, judge-reliability) is drawn from primary sources with
> verbatim quotes but was not put through the vote — marked **[primary-sourced]**. Two claims that the
> verifier **refuted** are quarantined in §9 and are *not* relied on anywhere in this record.
>
> **Evidence provenance:** the tool/standards survey was produced by a fan-out deep-research pass (25
> primary sources → 117 extracted claims → adversarial verification). Target-specific claims are cited
> to `../openemr-base-clean` by `path:line`, consistent with [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

---

## 1. Decision in one paragraph

The evidence supports a **clean three-layer split**, not an all-build or all-buy answer:

1. **CONFIGURE conventional scanners for the web/code attack surface.** Burp Suite Professional and
   OWASP ZAP scan the target's authenticated HTTP/API surface and are driveable headlessly by our
   Orchestrator; Semgrep covers the FastAPI/dependency code layer. **None of them does LLM adversarial
   testing** — their only "AI" features are AI-*assisted triage* (Burp) and AI-*assisted request
   generation* (ZAP), not adversarial probing of an LLM target. So they cover the OWASP *Web* Top 10
   layer and leave the entire OWASP *LLM* Top 10 layer uncovered.
2. **BUILD-ON two vendor-backed open-source substrates for the LLM attack + scoring layer.** NVIDIA
   **garak** (Apache-2.0) gives a broad probe taxonomy and a config-only REST generator that can point
   at our FastAPI/LangGraph endpoint with no code changes — but it is **single-turn/stateless** and
   authenticates only by static key or mTLS, not SMART/OAuth. Microsoft **PyRIT** (MIT) supplies
   exactly what garak lacks: **multi-turn orchestrators** (Crescendo/PAIR/TAP/Red-Teaming) and a
   **self-ask LLM-as-judge scoring** abstraction, and is the same engine Microsoft's own commercial
   Azure AI Red Teaming Agent is built on.
3. **BUILD the custom multi-agent layer that no tool provides** — the Orchestrator's coverage-driven
   prioritization, the SMART/OAuth + multi-turn state management, the *independent* Judge with
   calibration, the regression harness that distinguishes a fix from behavioral drift, and the
   Documentation agent with its human gate. This is the "reusable adversarial evaluation platform,"
   not a one-time scan, that the case study demands.

**Why not just buy a commercial LLM red-team platform?** The three we could source (Cisco AI Defense,
Palo Alto Prisma AIRS, Lakera Red) are capable and some now advertise multi-turn and OAuth — but for a
**hospital handling PHI**, the disqualifier is the same across all of them: **none discloses BAA
availability, PHI data-residency, or a self-hosted option** on its primary materials, and the strongest
options are **closed SaaS** that would require sending adversarial traffic (and any PHI it surfaces)
through a third-party cloud. A platform we build and run in-region needs no BAA with a third party
because no third party sees the data. That, plus the assignment's explicit requirement to *build* a
multi-agent system, settles it.

---

## 2. Methodology anchors (cited, not invented)

The platform maps its findings to recognized taxonomies so a CISO sees standards alignment, not a
bespoke severity scheme. All four are primary-sourced.

| Anchor | What it specifies about adversarial testing | Use in this platform |
|---|---|---|
| **OWASP Top 10 for LLM Applications 2025 (v2.0, published 2024-11-18)** [primary-sourced] | Ten categories: **LLM01** Prompt Injection, **LLM02** Sensitive Information Disclosure, **LLM03** Supply Chain, **LLM04** Data & Model Poisoning, **LLM05** Improper Output Handling, **LLM06** Excessive Agency, **LLM07** System Prompt Leakage, **LLM08** Vector & Embedding Weaknesses, **LLM09** Misinformation, **LLM10** Unbounded Consumption. Explicitly prescribes *"Conduct adversarial testing and attack simulations … treating the model as an untrusted user"* and *"Apply comprehensive AI Red Teaming … models can be finetuned to bypass published benchmarks."* | Primary taxonomy for the `owasp_mapping.llm_top10` field on every `ConfirmedExploit`. LLM07/LLM08 are directly relevant to a RAG-backed FHIR chatbot. |
| **OWASP Web Top 10 (2021; 2025 revision in progress)** [primary-sourced] | 2021 categories the engineering requirement names — broken access control, injection, insecure design, vulnerable components, auth failures, logging failures, SSRF. *(A 2025 revision exists that elevates Software Supply Chain Failures to A03; we track it but map to the 2021 categories the assignment enumerates.)* | `owasp_mapping.web_top10` for the conventional-surface findings Burp/ZAP produce. |
| **MITRE ATLAS** [primary-sourced] | Public knowledge base of adversary TTPs against AI systems; a fork of ATT&CK; distributed as **STIX 2.1** (`stix-atlas-attack-enterprise.json`) so findings can be mapped to a standard AI-threat taxonomy programmatically; ships real-incident case studies. | Technique-level tagging of attacks; the STIX bundle lets the platform map findings to ATLAS TTPs automatically. |
| **NIST AI 600-1 — Generative AI Profile (July 2024)** [primary-sourced] | Companion to AI RMF 1.0 (per EO 14110). **Defines AI red-teaming** as *"exercises … conducted in a controlled environment and in collaboration with AI developers … to identify potential adverse behavior … and stress test safeguards."* Action **MS-2.7-007** names the attack classes red-teaming must assess: *prompt injection, adversarial examples/prompts, data poisoning, membership inference, model extraction, sponge examples.* Enumerates 12 GAI risk categories including **Data Privacy** (health/PII leakage) and **Information Security**. Distinguishes **direct vs. indirect** prompt injection. | The authoritative, quotable definition of AI red-teaming for the CISO briefing, and the GOVERN/MAP/MEASURE/MANAGE structure the platform's controls map onto. |

**Takeaway:** every attack category in the threat model and every severity call the Documentation Agent
makes is anchored to one of these, so the platform is defensible as *standards-aligned*, not
idiosyncratic.

---

## 3. Evaluation criteria

Each tool is scored against what *this* platform actually needs:

- **C1 — LLM adversarial coverage:** does it generate/mutate prompt-injection, jailbreak, PHI-exfil,
  multi-turn attacks against an LLM *target*?
- **C2 — Multi-turn / stateful:** can it carry conversation state across turns (the target replays 40
  turns verbatim — `chat/service.py:542-592`)?
- **C3 — Authenticated (SMART/OAuth):** can it acquire and refresh a per-physician OAuth session?
- **C4 — Autonomous & continuous:** coverage-driven prioritization, regression on target change, not a
  one-shot scan?
- **C5 — Independent evaluation:** an evaluator separable from the attack engine (the core assignment
  constraint)?
- **C6 — Driveable as a subordinate:** exposes an API/CLI our Orchestrator can drive rather than
  replace?
- **C7 — PHI/hospital fit:** self-hostable / BAA / data-residency for a system handling PHI?

---

## 4. Tool-by-tool evaluation

### 4.1 Burp Suite (Professional & DAST/Enterprise) — **CONFIGURE, for the web surface only**

**Covers** [verified 3-0]: Burp Suite Professional is a best-in-class DAST for the conventional web/API
surface, including authenticated flows. Its 2025 "Burp AI" feature set (Professional 2025.2) adds a
Repeater **Explainer**, an agentic **Explore Issue** that auto-generates PoCs and attempts
exfiltration/escalation, AI-powered false-positive reduction, and AI-generated login sequences. It is
**driveable programmatically** through the **Montoya extension API** (`Ai.isEnabled()`,
`Prompt.execute(Message…)`, `enhancedCapabilities()→AI_FEATURES`), with 10,000 free AI credits — so our
Orchestrator can run it as an in-process Java extension.

**Falls short here** [verified 3-0]: the official capabilities page surfaces **no dedicated LLM or
prompt-injection scan check.** Burp AI is AI-*assisted triage of web findings*, not adversarial testing
of an LLM target. It fails **C1, C2, C5** outright. Pricing for Burp Suite DAST (formerly Enterprise) is
**not public** — custom-quoted only, with third-party estimates ranging wildly ($6k–$200k+/yr), so it
is not budgetable without a sales cycle.

**Verdict:** **Configure** for the OWASP *Web* Top 10 surface (broken access control, injection, SSRF,
misconfig against the 24 REST endpoints), driven as a subordinate by the Orchestrator. **Does not touch
the LLM attack layer.**

*Sources: portswigger.net/burp/ai/capabilities, .../extensions/creating/ai-features, .../burp/dast/pricing.*

### 4.2 OWASP ZAP — **CONFIGURE, for the web surface only**

**Covers** [verified 3-0]: ZAP's **Automation Framework** is configured by a single declarative YAML,
is container-independent, supports **all** of ZAP's authentication mechanisms, and runs **headless** via
`-autorun` with add-on install/update flags and clean **exit codes (0 success / 1 error / 2 warnings)**
— an ideal subordinate surface for CI-driven, orchestrator-triggered scans. Free and open-source.

**Falls short here** [verified 3-0]: ZAP's much-touted "LLM support" (in the OpenAPI add-on) uses an LLM
to *analyze an OpenAPI definition and generate sequences of HTTP calls for subsequent conventional
scanning* — *"These requests will be added to the ZAP history, allowing you to scan and test the API
endpoints."* The LLM is a **request-seeding front-end**, not an adversarial tester; there is **no
prompt-injection/jailbreak probing of an LLM system-under-test.** It fails **C1, C2, C5**. It also has
**no native SMART-on-FHIR/OAuth** method — OAuth requires a custom script-based auth component, and
unattended token refresh is nontrivial (partial **C3**).

**Verdict:** **Configure** as the free, scriptable DAST for the web surface, complementary to Burp.
**Does not touch the LLM attack layer.**

*Sources: zaproxy.org/docs/automate/automation-framework/, .../addons/openapi-support/llm/.*

### 4.3 Semgrep — **CONFIGURE, for the code layer only**

**Covers** [primary-sourced pricing; coverage by inference]: static analysis (SAST) and software-
composition/supply-chain (SCA) over the FastAPI codebase and its dependencies. Pricing: **Free** (≤10
contributors / ≤10 repos), **Teams** from **$30/contributor/mo** (Code $30, Supply Chain $30, Secrets
$15 à la carte), **Enterprise** custom.

**Falls short here:** Semgrep is a **static** tool. It **cannot reason about runtime or behavioral LLM
vulnerabilities** — it cannot tell whether a prompt-injection actually steers the model, whether a
withhold held, or whether PHI leaked in generated prose. It fails **C1–C5** for the adversarial mission
by construction. *(Note: the deep-research pass verified Semgrep's pricing 3-0 but did not independently
verify its Python/FastAPI rule coverage; the "no runtime LLM reasoning" point is a sound inference from
its static nature, not a vote-verified claim.)*

**Verdict:** **Configure** for code-layer hygiene (supply-chain = OWASP Web A06/2021, dependency CVEs) —
useful, but orthogonal to the adversarial platform.

*Source: semgrep.dev/pricing/.*

### 4.4 NVIDIA garak — **BUILD-ON as the attack-probe substrate**

**Covers** [verified 3-0]: garak (Apache-2.0, ~8k stars, actively maintained through 2026) is NVIDIA's
LLM vulnerability scanner — *"checks if an LLM can be made to fail in a way we don't want … somewhat
similar to nmap/Metasploit but for LLMs."* It ships an **extensive probe taxonomy**: prompt injection,
encoding-based injection, jailbreaks (DAN, goodside, grandma), data/training leakage (`leakreplay`),
malware/malicious-code generation, package hallucination, XSS/web-injection, glitch tokens, and
Unicode-perturbation. Its generic **RestGenerator lets us point garak at our FastAPI/LangGraph endpoint
by config alone** (`$INPUT` substituted into a request template, or a JSON body via
`req_template_json_object`; URI/method/headers/response-JSONPath all config-driven) — **no code
changes** to target our chat endpoint. v0.15.0 also added an **"Agent breaker" probe** that exercises a
target's tools.

**Falls short here** [verified 3-0] — this is precisely where the custom layer earns its keep:
- **C2 fails:** garak's REST path is **single-turn/stateless** — it substitutes only
  `prompt.last_message().text` and does **not** serialize conversation history (the source even carries
  an unresolved `# should this support a serialized Conversation?`). It **cannot conduct the target's
  40-turn multi-turn attacks** on its own.
- **C3 fails:** the REST generator authenticates only by **static API key** (`$KEY`) or **mTLS client
  cert** (v0.15.0, 2026-05-01) — **no OAuth/SMART bearer-token acquisition or refresh.** Our
  SMART-authenticated target requires the orchestrator to acquire the token and inject it as a static
  header per run.
- **C4 partial:** garak runs a scan; it has no coverage-driven prioritization, regression-on-change, or
  independent-Judge notion.

**Verdict:** **Build-on.** Import garak's probes and RestGenerator as a **subordinate attack engine**;
the custom Orchestrator supplies OAuth, multi-turn state, prioritization, and the independent Judge that
garak does not have.

*Sources: github.com/NVIDIA/garak, reference.garak.ai/.../rest.html, github.com/NVIDIA/garak/releases.*

### 4.5 Microsoft PyRIT — **BUILD-ON as the multi-turn + scoring substrate**

**Covers** [verified 3-0]: PyRIT (MIT) is Microsoft AI Red Team's framework to *"proactively identify
risks in generative AI systems."* It supplies exactly what garak's REST path lacks:
- **Multi-turn orchestrators** — Crescendo, PAIR, Red Teaming, and Tree-of-Attacks-with-Pruning (TAP),
  unified under a `MultiTurnOrchestrator` base with a standardized component config: `objective_target`,
  an `adversarial_chat` attacker LLM with its own system prompt, `prompt_converters` to mutate prompts,
  an `objective_scorer`, and a `max_turns` bound. This is the multi-turn machinery for **C2**.
- **Self-ask LLM-as-judge scoring** — `SelfAskTrueFalseScorer`, `SelfAskLikertScorer`,
  `SelfAskFloatScaleScorer`, plus `Refusal`, `InsecureCode`, and `PromptShield` scorers — a ready
  scoring abstraction (a substrate for the Judge's LLM tier, **C5**).
- **Maturity:** Microsoft reports 100+ red-team operations with it (self-reported), and its **own
  commercial Azure AI Red Teaming Agent is built on PyRIT** — the strongest possible signal that PyRIT
  is a *foundation to build on*, not a competitor. That product uses **Attack Success Rate (ASR)** as
  its headline metric, which we adopt as a defensible top-line number for the CISO.

**Falls short here:** PyRIT is a library, not a platform — no coverage-driven Orchestrator, no
regression harness, no Documentation agent, no human gates, no SMART/OAuth target auth out of the box.
And its scorers are only a *substrate* for our Judge, not an *independent* Judge — using PyRIT's
`adversarial_chat` and its scorer from the same model family would violate our independence invariant
(§6), so we drive the scorer with a **different family** than the attacker. **Currency caveats:** PyRIT
v0.14.0 renamed `Orchestrator`→`Attack` (class names above may be deprecated aliases); the canonical repo
moved `Azure/PyRIT`→`microsoft/PyRIT`. See §9 — the specific `run_attack_async`/`OrchestratorResult`
programmatic API was **refuted** by the verifier, so we do **not** assume that integration surface; we
treat PyRIT as an importable/extendable framework and pin the integration to the current release at
build time.

**Verdict:** **Build-on.** Inherit PyRIT's multi-turn orchestrators and self-ask scorers; wrap them in
the custom Orchestrator + independent Judge + harness.

*Sources: github.com/microsoft/PyRIT (formerly Azure/PyRIT), arxiv.org/abs/2410.02828, azure.github.io/PyRIT/blog/2024_12_3.html, learn.microsoft.com/.../ai-red-teaming-agent.*

### 4.6 Commercial LLM red-team platforms — **DO NOT BUY (for a PHI target)**

Three vendors could be sourced with primary evidence; the rest of the requested list could not (see §8).

| Vendor | What it does [primary-sourced] | Deployment | PHI/BAA signal |
|---|---|---|---|
| **Cisco AI Defense** (ex-Robust Intelligence, acquired Oct 2024 ~$400M) | "Explorer Edition" agentic AI red teaming; 200+ risk subcategories (incl. sensitive-data extraction); **single + adaptive multi-turn**; mapped to Cisco's AI Security framework; a run in ~20 min | **Free self-service SaaS** (explorer.aidefense.cisco.com, launched 2026-03-23) | **No BAA / PHI-residency disclosed** |
| **Palo Alto Prisma AIRS — AI Red Teaming** | 50+ techniques **mapped to OWASP Top 10 + NIST AI RMF**; **multi-turn** (Feb 2026); **OAuth2.0 token refresh** (Mar 2026); dynamic agent profiles the target; tests multi-agent systems | SaaS (self-hosted not disclosed) | **No pricing, API, BAA, or residency disclosed** |
| **Lakera Red** (owned by Check Point) | Automated AI red teaming: prompt injection, indirect injection, jailbreaks, data leakage, unauthorized actions, multilingual/multimodal | **SaaS** (platform.lakera.ai), free tier + sales-gated | **No HIPAA/BAA/residency/SOC2 on the product page** |

**Why not buy** — three reasons, in CISO order:
1. **PHI residency / BAA.** For a system handling PHI, adversarial traffic (and any PHI a successful
   exfil surfaces) would transit a third-party cloud. **None** of these discloses a BAA or a
   self-hosted/in-region option on its primary materials. A platform we run in-region needs no BAA
   because no third party sees the data.
2. **Assignment constraint.** The case study explicitly requires *building* a multi-agent system with an
   *independent* Judge, coverage-driven Orchestrator, and regression harness — a black-box SaaS scanner
   does not satisfy "define each agent, its inputs/outputs, its trust level, and how it coordinates."
3. **Extensibility & lock-in.** A bought scanner cannot be extended to probe *this* target's specific
   admitted weaknesses (the un-screened prose narration, the ~0.01 OCR confidence floor, the 404
   existence-oracle unification) the way a custom Red Team seeded from our own threat model can.

**These vendors are useful as a capability benchmark** — Prisma's OAuth-refresh + multi-turn and Cisco's
200-subcategory taxonomy are exactly the features our custom layer must match — but they are **not the
build path for a hospital PHI target.**

*Sources: blogs.cisco.com/ai/introducing-cisco-ai-defense-explorer, paloaltonetworks.com/prisma/ai-red-teaming, lakera.ai/ai-red-teaming.*

---

## 5. What we inherit vs. what we build

| Capability | Source | Build or inherit |
|---|---|---|
| LLM attack probes (injection, jailbreak, leakage, encoding, agent-tool) | **garak** | inherit |
| Config-only REST targeting of the chat endpoint | **garak RestGenerator** | inherit (+ our OAuth header injection) |
| Multi-turn orchestrators (Crescendo/PAIR/TAP) | **PyRIT** | inherit |
| Self-ask scoring primitives | **PyRIT scorers** | inherit (as Judge LLM-tier substrate, different family) |
| Web/API DAST on the 24 endpoints | **Burp + ZAP** | configure (driven as subordinates) |
| Code/supply-chain hygiene | **Semgrep** | configure |
| **SMART/OAuth token acquisition + refresh** | — | **build** (no tool does it for our target) |
| **Multi-turn state against the 40-turn replay surface** | — | **build** (garak can't; PyRIT's is generic) |
| **Coverage-driven Orchestrator** (deterministic prioritization) | — | **build** |
| **Independent Judge** (deterministic pre-check + calibrated panel) | — | **build** |
| **Regression harness** (fix-vs-drift stability check) | — | **build** |
| **Documentation agent + human gate + data-quality validation** | — | **build** |
| **Observability substrate the Orchestrator reads** | — | **build** |

The build surface is the **coordination, independence, and continuity** layer — exactly the layer the
case study says a static test runner and a single scanner cannot provide.

---

## 6. Evidence that Judge independence & calibration matter (not assertion)

The single most-scrutinized design choice — a Judge *independent of the attack engine* — is backed by
published evidence, so it survives a CISO's "prove it."

- **Judges have named, documented biases.** Zheng et al. (*Judging LLM-as-a-Judge with MT-Bench and
  Chatbot Arena*, NeurIPS 2023, arXiv 2306.05685) empirically document **position bias, verbosity bias,
  and self-enhancement (self-preference) bias** [primary-sourced]. This is why we do **not** let the
  attacker's family grade its own output.
- **Self-preference is reduced by a diverse panel.** Verga et al. (*Replacing Judges with Juries*, arXiv
  2404.18796, Apr 2024) show a **Panel of LLM evaluators (PoLL) from disjoint model families**
  outperforms a single large judge and *"exhibits less intra-model bias due to its composition of
  disjoint model families"* — while being *"over seven times less expensive"* [primary-sourced]. This
  is the direct evidence for our **multi-vote panel on high-severity verdicts** and for using a **model
  family different from the attacker**.
- **Position bias is systematic, not noise.** A dedicated study finds position bias *"is not due to
  random chance and varies significantly across judges and tasks,"* is driven by the **quality gap
  between candidates** (judges are least reliable when candidates are close), and introduces reusable
  metrics — **repetition stability, position consistency, preference fairness** [primary-sourced]. We
  adopt these as Judge self-checks.
- **Self-consistency ≠ human agreement — calibration is mandatory.** A survey of malicious-code refusal
  corpora notes GPT-4-to-human agreement of only **Pearson r=0.59** on conversational safety annotation
  (Movva et al.), warning that *"an LLM judge agreeing strongly with itself across runs can still
  diverge substantially from a human rater"* [primary-sourced]. Its recommended standard — a
  **vendor-diverse panel + a 3-of-5 consensus rule + a Fleiss' κ reliability statistic with bootstrap
  CI** — is precisely the calibration mechanism in [`ARCHITECTURE.md §4.3/§13`](../../ARCHITECTURE.md)
  (we use **Cohen's κ** against a frozen gold set for the single-judge-vs-gold case, and a panel with
  consensus for high-severity).
- **A strong judge *can* be trusted once calibrated.** Zheng et al. also show GPT-4 reaches **>80%
  agreement with human preference — the same as human-to-human** [primary-sourced]. So an LLM Judge is
  viable *when calibrated against a human/gold baseline*, which is exactly the bar our calibration gate
  enforces before it is trusted.

**Conclusion for the CISO:** Judge independence, a diverse panel on high-stakes calls, and κ-based
calibration against a gold set are **established mitigations from the literature**, not choices we
invented.

---

## 7. Evidence for the model-per-role choice (hosted low-refusal open-weight attacker, Claude Judge)

The decision to power the Red Team with a **low-refusal open-weight model** (Nous Hermes 4, served via
OpenRouter) and the Judge with **Claude** is evidence-backed, addressing the case study's explicit note
that *"commercial frontier models are often trained to refuse offensive security workflows"* and that
*"LLM cost … can run up tokens very quickly."*

- **Frontier models do refuse — but unreliably, in both directions.** Meta's **CyberSecEval 2** (arXiv
  2404.13161) introduces a **False Refusal Rate (FRR)** metric and finds that *"conditioning an LLM to
  reject unsafe prompts can cause the LLM to falsely reject … benign prompts, which lowers utility"*
  [primary-sourced] — i.e., safety-tuned frontier models **over-refuse borderline security prompts**,
  the failure mode that makes them unreliable for *generating* offensive test payloads. The same work
  finds prompt-injection attacks succeed **26–41%** of the time across tested models [primary-sourced].
- **Refusal is inconsistent and framing-dependent.** A 2025/2026 survey finds frontier models *"do not
  reliably refuse malicious-code requests,"* that **natural-text framings elicit lower refusal than
  code framings**, and documents a **"safety-capability inversion"** where more-capable models produce
  *more* effective harmful output [primary-sourced]. Depending on a frontier API to reliably *either*
  refuse or comply is unsound; a **purpose-built low-refusal model removes that variable** from the
  attack generator. **Nous Hermes 4** is exactly that — SOTA-low-refusal on RefusalBench, US-origin
  (Nous Research, Meta-Llama-3.1 base) [verified 2026-07-21].
- **Why hosted, not local.** An earlier design ran a *local* open-weight model for ≈$0/token; we moved
  the attacker to a **hosted endpoint (Hermes 4 via OpenRouter)** because a 32 GB dev box caps it at a
  much weaker model class and a hosted endpoint is far more resilient for a continuous run — while cheap
  serverless keeps the highest-volume role at pennies/turn (~$0.0014 on Hermes-70B, ~$0.011 on
  Hermes-405B) [405B pricing verified 2026-07-21 on OpenRouter; 70B figure reported, volatile — re-check
  before committing volume]. The cost lever survives; only its *mechanism* moved from local to serverless.
- **Why Hermes over DeepSeek as primary — provenance.** DeepSeek-R1 is the *measured* strongest
  open-weight attacker in the jailbreak literature [reported, not independently re-verified], but its
  **hosted API sends data to China and is flagged as a HIPAA / FAR Section-889 concern for healthcare**
  (state-level bans; analyst consensus) [verified 2026-07-21]. Leading with a PRC-origin model as the
  always-on attacker in a PHI-sensitive tool is an avoidable liability, so **DeepSeek is a
  CISO-sign-off-gated escalation only** (open weights on US infra if cleared). Hermes 4 gives most of
  the attacker capability with a clean US-origin provenance story.
- **Capability ceiling favors a division of labor.** CyberSecEval 2 also notes *"further work is needed
  for LLMs to become proficient at exploit generation"* and that **coding-capable models outperform**
  on offensive tasks [primary-sourced] — supporting a design where a cheap hosted open-weight model does
  high-volume *mutation* and the expensive reasoning is reserved for the Judge, not spent on every
  attack variant.

**Conclusion:** a **US-origin, low-refusal, hosted open-weight model (Hermes 4)** for the highest-volume
attack role and a **different-family Claude** for the independent Judge is grounded in published
behavior, not convenience — satisfying the cost constraint (mutation at pennies/turn), the independence
constraint (§6), and a hospital CISO's provenance / PHI-residency scrutiny (the attacker sees synthetic
data only; no PRC-origin model is in the runtime path).

**On attacker *structure* (single agent vs. a collaborating squad).** Neither garak nor PyRIT
orchestrates *multiple collaborating attacker agents* — both are single-attacker (+ separate scorer)
frameworks — so a multi-agent "attack squad" would be custom, unsupported engineering. The adversarial
literature also shows measured jailbreak gains come from *search / iteration / retries* (e.g. TAP's tree
search), not from multiple collaborating agents, and multi-agent worsens reproducibility. We therefore
default to a **single strong attacker with tree search + role-phased prompting** and defer the squad as
a gated A/B experiment — full rationale in [`ARCHITECTURE.md §4.2`](../../ARCHITECTURE.md).

---

## 8. Decision matrix

| | C1 LLM adv. | C2 Multi-turn | C3 SMART/OAuth | C4 Autonomous/continuous | C5 Independent judge | C6 Driveable | C7 PHI fit | Decision |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| Burp Suite Pro/DAST | ✗ | ✗ | ~ | ~ | ✗ | ✓ (Montoya) | self-host ✓ | **Configure** (web surface) |
| OWASP ZAP | ✗ | ✗ | ~ (script) | ✓ (CI) | ✗ | ✓ (`-autorun`) | self-host ✓ | **Configure** (web surface) |
| Semgrep | ✗ | ✗ | n/a | ✓ (CI) | ✗ | ✓ (CLI) | self-host ✓ | **Configure** (code layer) |
| garak | ✓ (probes) | ✗ | ✗ (key/mTLS) | ~ (scan) | ✗ | ✓ (REST/CLI) | self-host ✓ | **Build-on** (attack substrate) |
| PyRIT | ✓ | ✓ | ✗ | ~ (lib) | ~ (scorer only) | ✓ (library) | self-host ✓ | **Build-on** (multi-turn + scoring) |
| Cisco AI Defense | ✓ | ✓ | ~ | ✓ | ✗ (black box) | ~ | **SaaS, no BAA** | **Don't buy** (PHI) |
| Palo Alto Prisma AIRS | ✓ | ✓ | ✓ (OAuth) | ✓ | ✗ (black box) | ~ | **SaaS, no BAA** | **Don't buy** (PHI) |
| Lakera Red | ✓ | ~ | ~ | ✓ | ✗ (black box) | ~ | **SaaS, no BAA** | **Don't buy** (PHI) |
| **Custom multi-agent platform** | ✓ | ✓ | ✓ | ✓ | ✓ | — | **self-host, in-region** | **Build** (the coordination layer) |

✓ = yes · ~ = partial/with work · ✗ = no. "Configure/Build-on" tools are components *inside* the custom
platform, not alternatives to it.

---

## 9. Honesty ledger — refuted claims and coverage gaps

**Refuted by adversarial verification (NOT relied on anywhere above):**
1. *"garak added a dedicated multi-turn GOAT probe in v0.15.0"* — **refuted 0-3.** We therefore do **not**
   claim garak can do multi-turn on its own; the record treats garak's REST path as single-turn
   (§4.4), which is the verified position.
2. *"PyRIT exposes `run_attack_async(...)` returning `OrchestratorResult` and `run_attacks_async`
   parallelization as a stable driveable API"* — **refuted 1-2.** We therefore do **not** assert a
   specific PyRIT programmatic API surface; we commit only to PyRIT being an importable/extendable
   framework and pin the exact integration to the current release at build time (§4.5).

**Coverage gaps in this survey (disclosed, not hidden):**
- **Non-sourced commercial vendors:** HiddenLayer, Protect AI (Palo Alto Recon), Haize Labs, Patronus
  AI, Adversa AI, CalypsoAI, and Mindgard produced no verified findings. The "don't buy for PHI"
  conclusion rests on the three vendors we *could* source (Cisco, Palo Alto, Lakera) plus the general
  BAA/residency argument; it should be re-checked against any of these that a procurement process
  surfaces.
- **Semgrep rule coverage** for Python/FastAPI and LLM patterns was not vote-verified — only pricing
  was. The "static tools can't reason about runtime LLM behavior" point is sound by construction but
  not independently verified.
- **First-party figures** (e.g. PyRIT "100+ operations") are Microsoft self-reported and unaudited.

**Currency (as of 2026-07-20):** Burp AI is Professional 2025.2; garak mTLS is v0.15.0 (2026-05-01);
PyRIT is post-v0.14 (`Orchestrator`→`Attack` rename; repo now `microsoft/PyRIT`); OWASP LLM Top 10 is
v2.0 "2025" (2024-11-18); NIST AI 600-1 is July 2024. Vendor pages current as of the research date.

---

## 10. Sources

**Verified 3-0 (adversarial verification):**
- Burp AI — https://portswigger.net/burp/ai/capabilities · Montoya API — https://portswigger.net/burp/documentation/desktop/extensions/creating/ai-features · DAST pricing — https://portswigger.net/burp/dast/pricing
- ZAP Automation Framework — https://www.zaproxy.org/docs/automate/automation-framework/ · ZAP LLM add-on — https://www.zaproxy.org/docs/desktop/addons/openapi-support/llm/
- Semgrep pricing — https://semgrep.dev/pricing/
- garak — https://github.com/NVIDIA/garak · REST generator — https://reference.garak.ai/en/latest/garak.generators.rest.html · releases — https://github.com/NVIDIA/garak/releases
- PyRIT — https://github.com/Azure/PyRIT (now microsoft/PyRIT) · arXiv 2410.02828 — https://arxiv.org/abs/2410.02828 · orchestrator blog — https://azure.github.io/PyRIT/blog/2024_12_3.html · Azure AI Red Teaming Agent — https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent

**Primary-sourced (not vote-verified):**
- OWASP LLM Top 10 2025 — https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf · OWASP Top 10 2025 — https://owasp.org/Top10/2025/
- MITRE ATLAS — https://atlas.mitre.org/ · NIST AI 600-1 — https://airc.nist.gov/airmf-resources/profiles/ai-600-1/
- Cisco AI Defense — https://blogs.cisco.com/ai/introducing-cisco-ai-defense-explorer · Palo Alto Prisma AIRS — https://www.paloaltonetworks.com/prisma/ai-red-teaming · Lakera Red — https://www.lakera.ai/ai-red-teaming
- Judge reliability — Zheng et al. arXiv 2306.05685; Verga et al. arXiv 2404.18796; position-bias study arXiv 2406.07791; refusal-corpus survey arXiv 2605.20351
- Model refusal — CyberSecEval 2 arXiv 2404.13161; refusal-corpus survey arXiv 2605.20351

*Companion documents: [`ARCHITECTURE.md`](../../ARCHITECTURE.md) and
[`EVIDENCE_PACKET.md`](EVIDENCE_PACKET.md).*
