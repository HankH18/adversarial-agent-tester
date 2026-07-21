"""Performance / load-baseline harness.

A graded engineering deliverable: run a bounded volume of real attack executions
against the live target using the existing UNAUTHENTICATED seeds, with the
platform's self-throttle left ON, and capture platform-level performance metrics
(execution latency, target HTTP latency, throughput, Judge overhead, exploit-
storage throughput, peak memory). It never writes to the real data store — every
run is redirected to a fresh temp directory.
"""
from adversaryforge.perf.loadtest import LoadTestResult, run_loadtest

__all__ = ["LoadTestResult", "run_loadtest"]
