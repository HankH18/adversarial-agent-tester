"""Observability layer — the append-only data substrate the whole platform reads.

Not an afterthought: this is the input the Orchestrator reads to decide what to
attack next, and the evidence a human reads to trust the platform. Everything the
required observability questions need is a real query against this store:

  * coverage per category      → Store.coverage_by_category
  * pass/fail by version       → Store.passfail_rates
  * resilience trend           → Store.resilience_trend
  * open findings              → Store.open_findings
  * cost totals + burn rate    → Store.cost_summary / cost_by_agent (totals)
                                 and Store.cost_rate (USD/hour + cross-run scaling)
  * agent activity order       → Store.agent_timeline
"""
