"""AdversaryForge — a multi-agent adversarial evaluation platform for AI-assisted
clinical chatbots. Target #1: the OpenEMR Clinical Co-Pilot.

Design invariants (see ARCHITECTURE.md):
  1. The Judge is independent of the attack engine (separate agent + model family
     + information barrier).
  2. Deterministic by default; AI only where generation/semantic-judgment is
     irreducible.
  3. Autonomy is bounded by blast radius: read-mostly against the target,
     write-only against our own store, human gate before publishing criticals.
"""

__version__ = "0.1.0"
