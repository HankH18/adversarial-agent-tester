#!/usr/bin/env python
"""Standalone entrypoint for the AdversaryForge load/baseline performance harness.

Runs ~N attack executions against the LIVE target using the existing
UNAUTHENTICATED seeds (cheap endpoints; self-throttle left ON) and prints the
captured platform-level performance baseline. Writes nothing to the real data
store — the harness redirects ADVERSARYFORGE_DATA_DIR to a fresh temp dir.

Usage:
    .venv/bin/python scripts/run_loadtest.py [attacks]     # default 100
    .venv/bin/python scripts/run_loadtest.py --json        # machine-readable
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the repo root is importable when run as a bare script (the script's own
# directory, not the repo root, is what Python puts on sys.path[0]).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from adversaryforge.perf import run_loadtest
from adversaryforge.perf.loadtest import LoadTestResult


def _fmt_phase(p) -> str:
    return f"p50={p.p50_ms:>9.2f}  p95={p.p95_ms:>9.2f}  max={p.max_ms:>9.2f}  mean={p.mean_ms:>9.2f}  n={p.n}"


def _print_report(r: LoadTestResult) -> None:
    line = "─" * 78
    print(line)
    print("AdversaryForge — Load / Baseline Performance Report")
    print(line)
    print(f"target            : {r.target_url}  (version={r.target_version}, "
          f"authenticated={r.authenticated})")
    print(f"platform          : {r.platform}  python {r.python_version}")
    print(f"self-throttle     : max_concurrency={r.max_concurrency}  "
          f"min_request_gap_s={r.min_request_gap_s}  timeout_s={r.request_timeout_s}")
    print(f"seeds cycled      : {r.seeds_cycled} unauthenticated seeds")
    print(line)
    print(f"attacks executed  : {r.attacks_total}")
    print(f"wall clock        : {r.wall_seconds:.3f} s")
    print(f"throughput        : {r.throughput_attacks_per_s:.3f} attacks/sec")
    print(f"outcomes          : {r.outcomes}")
    print(line)
    print("latency (ms):")
    print(f"  execution/attack: {_fmt_phase(r.execution)}")
    print(f"  target HTTP     : {_fmt_phase(r.target_http)}")
    print(f"  judge overhead  : {_fmt_phase(r.judge)}")
    print(f"  storage/attack  : {_fmt_phase(r.storage)}")
    print(f"  burst (12x)     : {_fmt_phase(r.burst_http)}")
    print(line)
    print("storage throughput:")
    print(f"  store write ops : {r.store_write_ops}")
    print(f"  writes/sec      : {r.storage_writes_per_s:.1f}")
    print(f"  exploits stored : {r.exploits_stored}")
    print(line)
    print("memory:")
    print(f"  peak traced     : {r.peak_traced_mem_mb:.2f} MB (tracemalloc)")
    print(f"  peak RSS        : {r.peak_rss_mb:.1f} MB (getrusage)")
    print(line)
    print("isolation:")
    print(f"  temp db         : {r.temp_db_path}")
    print(f"  real db untouched: {r.real_db_untouched}")
    print(f"  real db before  : {r.real_db_before}")
    print(f"  real db after   : {r.real_db_after}")
    print(line)


def main() -> int:
    args = [a for a in sys.argv[1:]]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    attacks = int(args[0]) if args else 100

    result = run_loadtest(attacks)

    if as_json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        _print_report(result)

    if not result.real_db_untouched:
        print("WARNING: the real data store changed during the run!", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
