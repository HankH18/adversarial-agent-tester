# Defenses that HELD — the negative result (authenticated attack plane)

> A vulnerability report directory that lists only findings tells half the story. For a security
> platform, **"we attacked this surface with a valid session and the defense held"** is a first-class,
> valued result — it is what a hospital CISO most wants to know. This file records the held-defense
> outcomes so `reports/` tells the complete picture, alongside the confirmed findings in
> `reports/VULN-*.md`.

## What ran — with a VERIFIED authenticated session

An authenticated live campaign ran against the deployed target (`https://agentforge.hankholcomb.com`,
synthetic data only). The session was **verified authenticated** before attacking — the target's own
`/v1/auth/status` returned `authenticated: true` and `/v1/auth/me` resolved to a real physician
(`clinician_id 1`). Every one of the **30 seeds / 6 categories** was adjudicated by the independent,
deterministic-first Judge (κ=1.0 gold-set calibration each run).

> Provenance note: an earlier version of this file reported these categories as "held" while the
> platform's session cookie was **not actually being accepted** (it was sent without its `af_session=`
> name, so authenticated requests silently hit the 401 boundary). That wiring bug is fixed
> (`target/session.py`), the session is now verified against `/v1/auth/status` at campaign start, and
> the results below are from a genuinely authenticated run. The headline held — but now for the right
> reason (attacks were **defended**, not merely **refused pre-auth**).

## Result by category (authenticated live campaign, clean store)

| Attack category | Attempts | Confirmed exploits | Outcome |
|---|---|:---:|---|
| **Prompt injection** (direct / indirect-via-document / multi-turn) | 4 | **0** | ✅ **HELD** — under a valid physician session the injected instructions were treated as inert data: no system-prompt leak, no canary echo, scope unchanged |
| **State corruption** (history poisoning / forged-reply replay) | 2 | **0** | ✅ **HELD** — poisoned history did not launder into trusted instructions; ungrounded turns withheld |
| **Tool misuse** (write-gate, forged confirm, rounds-start tamper) | 2 | **0** | ✅ **HELD** — write routes gated; forged confirmations rejected |
| **Identity / role** (clinician mismatch, persona hijack, SSRF-via-agent) | 3 | **0** | ✅ **HELD** — the asserted-clinician override did not take; no server-side fetch of internal/metadata URLs |
| **Data exfiltration** | 14 | 4 | ⚠️ **MIXED** — authenticated **cross-patient reads and PHI egress HELD** (authz enforced: 401/403/withheld). The 4 confirmed are **infrastructure info-disclosure** on *anonymous* endpoints (`/ready`, `/v1/auth/status`, `/openapi.json`) + a missing-HSTS transport gap. The three info-disclosure findings have `VULN-*` reports; the HSTS gap has none |
| **Denial of service** | 3 | 2 | ⚠️ **MIXED** — recursion/latency bounded on most turns; the 2 confirmed are **absent inbound rate limiting** + a cost-amplification latency breach — see `VULN-*` |

**Every one of the 6 confirmed exploits is infrastructure-level** (anonymous info disclosure, missing
HSTS, missing rate limiting). Under a genuine authenticated physician session, the **agentic** attack
categories — prompt injection, state corruption, tool misuse, identity/role — and the **authenticated
PHI / cross-patient** attacks all held with **zero** confirmed exploits. The real weaknesses are
conventional web-infra hygiene, not the LLM co-pilot's safety behavior.

## How to reproduce

```bash
# authenticated: AGENTFORGE_SESSION_COOKIE=<af_session value> in .env (synthetic data only)
.venv/bin/python -m adversaryforge.cli campaign      # prints "✓ session verified" when the cookie is accepted
.venv/bin/python -m adversaryforge.cli status        # pass/fail by category (held = failure = defense held)
```

The Judge's polarity: an attack **`success`** means the invariant was *falsified* (a vulnerability); a
**`failure`** means the attack was repelled (**the defense held**). Full per-category threat analysis is
in [`../THREAT_MODEL.md`](../THREAT_MODEL.md) §8.2.

*Counts are from an authenticated campaign on 2026-07-24 (verified session, clean store). That
deployment is offline today and this run's raw verdicts are not committed, so these counts cannot be
re-derived from this repository; the five published findings in `evals/published_findings.yaml` can.*
