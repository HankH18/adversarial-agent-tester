# `/contracts` — versioned inter-agent message schemas

Every message that crosses an agent boundary in AdversaryForge is a typed
[`adversaryforge.contracts`](../adversaryforge/contracts/__init__.py) model. This
directory holds the **canonical JSON Schemas** generated from those models. They
are the public, language-neutral contract: a producer emits a message and a
consumer validates it against the schema here, so the two sides can never
silently drift.

- **Generated, never hand-edited.** Run
  [`scripts/export_contracts.py`](../scripts/export_contracts.py) to regenerate
  `<ModelName>.v1.schema.json` for all seven contracts.
- **Guarded by tests.** [`tests/test_contracts.py`](../tests/test_contracts.py)
  proves (a) a real sample instance validates against the on-disk schema
  (producer == consumer) and (b) the on-disk schema still equals the live model
  (the drift tripwire below).

## Producers and consumers

| Contract | Produced by | Consumed by |
| --- | --- | --- |
| `CampaignDirective` | Orchestrator | Red Team |
| `AttackAttempt` | Red Team | Judge |
| `Verdict` | Judge | Observability, Documentation, Harness |
| `ConfirmedExploit` | Judge | Documentation, Harness |
| `RegressionCandidate` | Judge | Harness |
| `VulnReport` | Documentation | Human / report store |
| `AgentError` | **Every** agent | Orchestrator, Observability |

> Trust boundary: the Red Team sets `technique` / `intent` / `attacker_confidence`
> on an `AttackAttempt`, but the Judge is constructed to read only `.transcript`,
> `.expected_safe`, and the invariant — the information barrier that keeps the
> evaluator independent of the attack engine.

## Versioning policy

- The published version is **v1**. Every file is `*.v1.schema.json` and carries
  a `"version": "v1"` marker plus a stable `$id`
  (`https://adversaryforge/contracts/<name>/v1`).
- **Non-breaking changes** (adding an optional field with a default, widening
  docs) may ship under v1: change the model, re-run the export script, and the
  drift-guard test keeps everyone honest.
- **A breaking change** — removing/renaming a field, making an optional field
  required, tightening a type or enum, changing semantics — requires **all** of:
  1. a **version bump** (`v2`), producing `<ModelName>.v2.schema.json` alongside
     the retained `v1` file;
  2. a **migration note** describing how producers/consumers move v1 → v2;
  3. a **`CHANGELOG.md` entry**; and
  4. **updated contract tests** covering the new version.
- The **drift guard** (`test_drift_guard_disk_matches_model`) fails CI the moment
  a contract model changes without a matching re-export. A red drift test is the
  signal to follow the policy above — not to edit the test.
