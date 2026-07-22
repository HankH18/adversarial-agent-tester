# Medium-severity Denial of Service: INV-RATE-LIMIT falsified in the AgentForge Clinical Co-Pilot

| Field | Value |
| --- | --- |
| Report ID | `VULN-64e3b7c7c3` |
| Exploit ID | `ex_d7c755c4b5f6` |
| Severity | **MEDIUM** |
| Category | Denial of Service |
| Status | published |
| OWASP | A04:2021-Insecure Design, LLM10:2025-Unbounded Consumption |
| Requires human approval | no |

## Summary

An adversarial attempt in the Denial of Service category falsified the INV-RATE-LIMIT invariant of the AgentForge Clinical Co-Pilot. Observed: No throttling across 12 rapid requests (no 429) — rate limiting absent; enables cost amplification / brute force. The target should instead have exhibited: At least one 429/Retry-After under a rapid burst.

## Clinical impact

The endpoint accepts unbounded request volume from a single session. Against a clinical assistant this is an availability risk during care — a flood degrades or denies the Co-Pilot for every clinician on the instance — and, paired with an oracle, enables high-volume enumeration (patient existence, ID sweeps).

## Reproduction

**1.** Authenticate to the target as a clinician (https://agentforge.hankholcomb.com). Synthetic demo data only. If no session is available, use the unauthenticated surface — the exploit below reproduces without one.

**2.** Send the following request to the Co-Pilot:

```
[burst x12] GET /health
```

**3.** Observe the target's response (HTTP 200):

```
burst statuses=[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200] in 214ms
```

**4.** Confirm the observed behavior below is present (and differs from the expected safe behavior). The finding reproduces when it is.

## Observed behavior

No throttling across 12 rapid requests (no 429) — rate limiting absent; enables cost amplification / brute force.

## Expected (safe) behavior

At least one 429/Retry-After under a rapid burst.

## Remediation

Add per-identity and per-IP inbound rate limiting and concurrency caps at the gateway (token bucket, e.g. N req/min/clinician) with HTTP 429 + Retry-After. Alert on sustained saturation. Do not rely on client-side throttling.

## Fix validation

Add a deterministic regression case for INV-RATE-LIMIT to the harness and re-run the adversarial suite against the patched target; the finding is fixed only when that case (and the full category) pass on the new target version.
