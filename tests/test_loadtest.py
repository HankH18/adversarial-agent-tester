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

from types import SimpleNamespace

from adversaryforge.contracts import AttackCategory, Severity, TranscriptTurn
from adversaryforge.perf.loadtest import (
    Phase,
    _build_exploit,
    _db_stat,
    _pct,
    _target_latencies,
)


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


# ── _target_latencies ────────────────────────────────────────────────────────
def _turn(role: str, raw):
    """A stand-in for a transcript turn: _target_latencies only reads .role/.raw."""
    return SimpleNamespace(role=role, raw=raw)


def test_target_latencies_splits_singles_and_bursts():
    attempt = SimpleNamespace(transcript=[
        _turn("attacker", None),                                    # not target → skip
        _turn("target", {"_latency_ms": 12.5}),                     # single
        _turn("target", {"_latency_ms": 30, "_burst_statuses": [200] * 12}),  # burst
        _turn("target", {}),                                        # no _latency_ms → skip
        _turn("target", None),                                      # None raw → skip
        _turn("target", {"_latency_ms": 8.0}),                      # single
    ])
    singles, bursts = _target_latencies(attempt)
    assert singles == [12.5, 8.0]
    assert bursts == [30.0]
    # latencies are coerced to float even when the client stamped an int
    assert all(isinstance(x, float) for x in singles + bursts)


def test_target_latencies_empty_transcript():
    assert _target_latencies(SimpleNamespace(transcript=[])) == ([], [])


# ── _db_stat ─────────────────────────────────────────────────────────────────
def test_db_stat_absent_for_missing_path(tmp_path):
    assert _db_stat(tmp_path / "does-not-exist.sqlite") == "absent"


def test_db_stat_reports_size_and_mtime(tmp_path):
    f = tmp_path / "db.sqlite"
    f.write_bytes(b"hello")  # 5 bytes
    st = f.stat()
    assert _db_stat(f) == f"size=5B mtime={st.st_mtime_ns}"


# ── _build_exploit ───────────────────────────────────────────────────────────
def test_build_exploit_mirrors_promote_fields():
    transcript = [
        TranscriptTurn(role="attacker", content="do the bad thing"),
        TranscriptTurn(role="target", content="leaked", http_status=200),
    ]
    attempt = SimpleNamespace(
        attempt_id="att_1",
        category=AttackCategory.data_exfiltration,
        subcategory="phi_leak",
        target_invariant="inv_no_phi",
        transcript=transcript,
        expected_safe="must withhold PHI",
        owasp_web=[],
        owasp_llm=[],
    )
    verdict = SimpleNamespace(
        verdict_id="ver_1",
        severity=Severity.high,
        rationale="the target disclosed PHI",
    )

    exploit = _build_exploit(attempt, verdict, "v2.3.1")

    # identity linkage
    assert exploit.attempt_id == "att_1"
    assert exploit.verdict_id == "ver_1"
    # faithfully copied fields (str-enums compare equal to their .value)
    assert exploit.category == AttackCategory.data_exfiltration
    assert exploit.severity == Severity.high
    assert exploit.target_invariant == "inv_no_phi"
    assert exploit.subcategory == "phi_leak"
    assert exploit.expected_safe == "must withhold PHI"
    assert exploit.observed == "the target disclosed PHI"
    assert exploit.target_version == "v2.3.1"
    # the minimal transcript is carried over turn-for-turn
    assert exploit.minimal_transcript == transcript
    # a fresh exploit id is minted each call
    assert exploit.exploit_id.startswith("ex_")
