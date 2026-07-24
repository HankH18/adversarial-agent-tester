# Remediation contract — from finding to fix

AdversaryForge already **finds**, **judges**, **documents**, and **regression-freezes** vulnerabilities.
The published-findings ledger is the bridge to the next step: an **agent that reads a confirmed finding and
fixes the target application's code**, closing the loop.

## The ledger — `evals/published_findings.yaml`

A committed, machine-readable record of the real exploits behind `reports/VULN-*.md`. It serves two jobs:

1. **Provenance & reproducibility.** The source exploits previously lived only in the git-ignored SQLite
   DB, so a fresh clone could not regenerate the reports or prove they came from real findings.
   `adversaryforge seed-published` loads the ledger into the store, after which `report` regenerates the
   `VULN-*.md` files **byte-for-byte** and `status`/`regress` work — no live campaign required.
2. **Remediation contract.** Each finding carries the fields a fixing agent needs to act.

### Per-finding shape

```yaml
findings:
  - exploit:            # verbatim ConfirmedExploit contract (category, invariant, severity,
      ...               # minimal_transcript, expected_safe, observed, OWASP mapping, …)
    seed_id: dos-rate-limit-absence   # the seed that produced it (regression replay)
    steps: [...]                       # the exact attack steps, for replay
    remediation:
      status: open                     # open | resolved
      affected_endpoint: "all routes (no inbound rate limiting)"
      target_code_hint: "agent/copilot/api/app.py — no inbound rate-limit middleware (app.py:99-212)"
      recommended_fix: "Add per-identity/IP token-bucket middleware returning 429 + Retry-After …"
```

- **`exploit` + `steps`** — *what broke and how to reproduce it* (the invariant violated, the transcript,
  the replayable steps).
- **`remediation.affected_endpoint` / `target_code_hint`** — *where to fix it* in the target repo
  (`../openemr-base-clean`). These are pointers, not guarantees — a remediation agent should confirm the
  location before editing.
- **`remediation.recommended_fix`** — *how to fix it* (the control to add), derived from the finding's
  invariant and the target's own documented limitations.

## The closed loop (the next step)

```
AdversaryForge campaign ─▶ Judge confirms ─▶ Documentation ─▶ published_findings.yaml (this ledger)
                                                                      │
                                                                      ▼
                                                   Remediation agent (NEXT): read a finding,
                                                   locate target_code_hint in ../openemr-base-clean,
                                                   propose/apply the recommended_fix
                                                                      │
                                                                      ▼
                        adversaryforge regress ◀── re-run the frozen case: the invariant now HOLDS
                        (status open ▶ resolved). If a later run re-fails it, the harness flags a
                        REAPPEARANCE — a fix that regressed.
```

The remediation agent is **not built here** — the ledger is the contract it will consume. Because every
finding is pinned to a versioned regression case (`docs/target/openapi-week2.PINNED.yaml`), a fix can be
*proven* by re-running `adversaryforge regress`: a red case turning green is a confirmed remediation, and a
green case turning red later is a reappearance. That is how "we fixed it" stops being a claim and becomes a
test result — the same discipline the platform applies to its own findings.

## Regenerate / inspect

```bash
adversaryforge seed-published   # load the ledger into a fresh store
adversaryforge report           # regenerate reports/VULN-*.md byte-for-byte
adversaryforge status           # the findings appear in coverage / open findings
adversaryforge regress          # replay each case (RED while the target is still vulnerable)
```
