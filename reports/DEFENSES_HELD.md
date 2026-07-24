# Defenses that HELD — the negative result (authenticated LLM attack plane)

> A vulnerability report directory that lists only findings tells half the story. For a security
> platform, **"we attacked this surface and the defense held"** is a first-class, valued result — it is
> what a hospital CISO most wants to know. This file records the held-defense outcomes so `reports/`
> tells the complete picture, alongside the confirmed findings in `reports/VULN-*.md`.

## What ran

Authenticated live campaigns against the deployed target (`https://agentforge.hankholcomb.com`,
SMART/OAuth session, synthetic data only) exercised all **6 attack categories / 30 seeds**
(`adversaryforge campaign` → `status`). The independent, deterministic-first Judge (κ=1.0 gold-set
calibration each run) adjudicated every attempt.

## Result by category (live, campaign-only)

| Attack category | Attempts | Confirmed exploits | Outcome |
|---|---|:---:|---|
| **Prompt injection** (direct / indirect-via-document / multi-turn) | 16 | **0** | ✅ **HELD** — refused pre-auth or withheld; no system-prompt leak, no canary echo, injected instructions treated as inert data |
| **State corruption** (history poisoning / forged-reply replay) | 10 | **0** | ✅ **HELD** — poisoned history did not launder into trusted instructions; ungrounded turns withheld |
| **Tool misuse** (write-gate, forged confirm, rounds-start tamper) | 7 | **0** | ✅ **HELD** — write routes gated (503/40x); forged confirmations rejected |
| **Identity / role** (clinician mismatch, persona hijack, SSRF-via-agent) | 12 | **0** | ✅ **HELD** — session identity not overridable; no server-side fetch of internal/metadata URLs |
| **Data exfiltration** | 47 | 16 | ⚠️ **MIXED** — cross-patient / PHI-egress **HELD** (authz enforced, 401/403/withheld); the confirmed successes are **infrastructure info-disclosure** on *anonymous* endpoints (`/ready`, `/v1/auth/status`, `/openapi.json`, `/status`) — see the `VULN-*` reports |
| **Denial of service** | 13 | ~6 | ⚠️ **MIXED** — recursion/latency bounded (**HELD**); the confirmed success is **absent inbound rate limiting** (cost-amplification / brute-force enabler) — see `VULN-*` |

**The four LLM-plane attack categories — prompt injection, state corruption, tool misuse, and
identity/role — recorded ZERO confirmed exploits.** Every confirmed finding in `reports/VULN-*.md` is
**infrastructure-level** (anonymous info disclosure, missing rate limiting / HSTS), not an LLM jailbreak.
That is the honest, defensible headline: under continuous adversarial pressure the *agentic* safety
invariants held; the real weaknesses are conventional web-infra hygiene.

## How to reproduce

```bash
# authenticated (needs AGENTFORGE_SESSION_COOKIE in .env); synthetic data only
.venv/bin/python -m adversaryforge.cli campaign      # runs all runnable seeds live
.venv/bin/python -m adversaryforge.cli status        # pass/fail by category (held = failure = defense held)
```

Note the Judge's polarity: an attack **`success`** means the invariant was *falsified* (a vulnerability);
a **`failure`** means the attack was repelled (**the defense held**). Full per-category threat analysis,
including the corrected false-positive story on the authenticated authz path, is in
[`../THREAT_MODEL.md`](../THREAT_MODEL.md) §8.2.

*Counts above are from the live authenticated campaign history on 2026-07-24 and will grow as more
campaigns run; the qualitative result — LLM-plane categories held, findings are infra-level — is stable
and reproducible.*
