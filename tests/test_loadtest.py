"""Pure-function tests for the perf harness math. docs/PERFORMANCE_BASELINE.md
publishes p50/p95 latency figures produced by `_pct` and `Phase.of`; those are
off-by-one-prone index computations backing a deliverable, with no other coverage.
These lock the arithmetic so a future edit that shifts an index turns a test red
instead of silently misreporting the baseline. No live target needed.

Expected values were computed by hand against the implementation (linear-interpolated
percentile, matching numpy's default) — e.g. _pct([10,20,30,40],95): k=3*0.95=2.85,
xs[2]+(xs[3]-xs[2])*0.85 = 30+10*0.85 = 38.5.
"""
from __future__ import annotations

from adversaryforge.perf.loadtest import Phase, _pct


def test_pct_median_interpolates():
    assert _pct([10.0, 20.0, 30.0, 40.0], 50) == 25.0


def test_pct_single_value_returns_it():
    assert _pct([5.0], 95) == 5.0


def test_pct_empty_is_zero():
    assert _pct([], 50) == 0.0


def test_pct_p95_linear_interpolation():
    # (n-1)*0.95 = 94.05 -> xs[94] + 0.05*(xs[95]-xs[94]) = 95 + 0.05 = 95.05
    assert round(_pct([float(i) for i in range(1, 101)], 95), 2) == 95.05


def test_pct_endpoints():
    xs = [10.0, 20.0, 30.0, 40.0]
    assert _pct(xs, 0) == 10.0
    assert _pct(xs, 100) == 40.0


def test_phase_of_empty_is_all_zero():
    p = Phase.of("x", [])
    assert (p.p50_ms, p.p95_ms, p.max_ms, p.mean_ms, p.n) == (0.0, 0.0, 0.0, 0.0, 0)


def test_phase_of_fixed_sample():
    p = Phase.of("x", [10.0, 20.0, 30.0, 40.0])
    assert (p.p50_ms, p.p95_ms, p.max_ms, p.mean_ms, p.n) == (25.0, 38.5, 40.0, 25.0, 4)
