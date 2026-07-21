"""Observability layer — the append-only data substrate the whole platform reads.

Not an afterthought: this is the input the Orchestrator reads to decide what to
attack next, and the evidence a human reads to trust the platform. Everything the
required observability questions need (coverage per category, pass/fail by version,
resilience trend, open findings, cost + burn rate, agent activity order) is a query
against this store.
"""
