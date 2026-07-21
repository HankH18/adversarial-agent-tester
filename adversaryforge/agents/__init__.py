"""The agent roles. Each is a distinct responsibility with its own trust level:

  * Orchestrator (trusted)  — strategy; deterministic target selection.
  * Red Team (untrusted)    — attack generation + mutation.
  * Judge (semi-trusted)    — independent evaluation; cannot act.
  * Documentation (gated)   — turns confirmed exploits into reports; human gate.

Agents never call each other directly — they exchange versioned contracts
(`adversaryforge.contracts`) through the orchestrator/graph.
"""
