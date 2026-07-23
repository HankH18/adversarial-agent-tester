"""Load / baseline performance harness for AdversaryForge.

What it does
------------
Executes ~N attack executions against the LIVE target by cycling the existing
UNAUTHENTICATED seeds (they hit cheap endpoints — /health, /ready, /openapi.json,
/v1/auth/status, and a bounded 12-request burst to /health). The platform's
self-throttle (``max_concurrency`` + ``min_request_gap_s``) is left ON so this
harness can never become the thing that DoSes a system physicians depend on.

For each attack it measures, in isolation, the four phases of the real pipeline:

  1. **execution**  — ``SeedExecutor.run`` (compile → throttled HTTP → transcript).
     This includes the self-throttle wait and the network round-trip, so it is the
     dominant term and is reported separately from the raw target latency.
  2. **target HTTP** — ``TargetResponse.latency_ms`` captured per request by the
     client, harvested from the transcript's target turns (bursts excluded — their
     latency is a 12-way aggregate, reported on its own).
  3. **judge**      — ``Judge.evaluate_attempt`` (the independent, deterministic
     adjudication behind the info barrier).
  4. **storage**    — ``record_attempt`` + ``record_verdict`` (+ ``record_exploit``
     on a success), i.e. the exploit-store write path.

Safety / isolation
-------------------
``ADVERSARYFORGE_DATA_DIR`` is pointed at a fresh ``tempfile.mkdtemp`` directory
*before* any ``Settings`` is built, so the run's SQLite file lands in the temp dir
and the real ``data/adversaryforge.sqlite`` is never touched. The harness records
the real DB's size+mtime before and after and reports whether it changed.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import sys
import tempfile
import time
import tracemalloc
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:  # `resource` is POSIX-only; keep the package import-safe on Windows.
    import resource
except ImportError:  # pragma: no cover - non-POSIX
    resource = None

from adversaryforge.agents.judge import Judge
from adversaryforge.config import Settings
from adversaryforge.contracts import ConfirmedExploit, Outcome
from adversaryforge.observability.store import Store
from adversaryforge.redteam.executor import SeedExecutor
from adversaryforge.redteam.seeds import Seed, SeedLibrary
from adversaryforge.target.adapter import agentforge_adapter
from adversaryforge.target.client import TargetClient
from adversaryforge.target.session import build_session


# ── result containers ──────────────────────────────────────────────────────
@dataclass
class Phase:
    """p50 / p95 / max (ms) plus the raw sample count for one pipeline phase."""

    name: str
    p50_ms: float
    p95_ms: float
    max_ms: float
    mean_ms: float
    n: int

    @staticmethod
    def of(name: str, samples_ms: list[float]) -> "Phase":
        if not samples_ms:
            return Phase(name, 0.0, 0.0, 0.0, 0.0, 0)
        return Phase(
            name=name,
            p50_ms=round(_pct(samples_ms, 50), 2),
            p95_ms=round(_pct(samples_ms, 95), 2),
            max_ms=round(max(samples_ms), 2),
            mean_ms=round(statistics.fmean(samples_ms), 2),
            n=len(samples_ms),
        )


@dataclass
class LoadTestResult:
    attacks_total: int
    wall_seconds: float
    throughput_attacks_per_s: float
    target_url: str
    target_version: str
    authenticated: bool
    # throttle config in force during the run
    max_concurrency: int
    min_request_gap_s: float
    request_timeout_s: float
    # per-phase latency distributions
    execution: Phase
    target_http: Phase
    judge: Phase
    storage: Phase
    burst_http: Phase  # 12-way concurrent /health burst, aggregate elapsed
    # storage throughput
    store_write_ops: int
    storage_writes_per_s: float
    exploits_stored: int
    outcomes: dict[str, int]
    # memory
    peak_traced_mem_mb: float
    peak_rss_mb: float
    # environment / provenance
    python_version: str
    platform: str
    seeds_cycled: int
    temp_db_path: str
    real_db_untouched: bool
    real_db_before: str
    real_db_after: str

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ── helpers ─────────────────────────────────────────────────────────────────
def _pct(values: list[float], pct: float) -> float:
    """Linear-interpolated percentile on a copy-sorted list."""
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    frac = k - lo
    return xs[lo] + (xs[hi] - xs[lo]) * frac


def _db_stat(path: Path) -> str:
    try:
        st = path.stat()
        return f"size={st.st_size}B mtime={st.st_mtime_ns}"
    except FileNotFoundError:
        return "absent"


def _target_latencies(attempt) -> tuple[list[float], list[float]]:
    """Return (single_request_latencies, burst_aggregate_latencies) from a
    transcript's target turns, using the ``_latency_ms`` the client stamped."""
    singles: list[float] = []
    bursts: list[float] = []
    for turn in attempt.transcript:
        if turn.role != "target":
            continue
        raw = turn.raw or {}
        lat = raw.get("_latency_ms")
        if lat is None:
            continue
        if "_burst_statuses" in raw:
            bursts.append(float(lat))
        else:
            singles.append(float(lat))
    return singles, bursts


def _build_exploit(attempt, verdict, target_version: str) -> ConfirmedExploit:
    """Minimal faithful mirror of Orchestrator._promote's exploit construction —
    just enough to exercise the real store write path under load."""
    return ConfirmedExploit(
        exploit_id="ex_" + uuid.uuid4().hex[:12],
        attempt_id=attempt.attempt_id,
        verdict_id=verdict.verdict_id,
        category=attempt.category,
        subcategory=attempt.subcategory,
        severity=verdict.severity,
        target_invariant=attempt.target_invariant,
        minimal_transcript=attempt.transcript,
        expected_safe=attempt.expected_safe,
        observed=verdict.rationale,
        owasp_web=attempt.owasp_web,
        owasp_llm=attempt.owasp_llm,
        target_version=target_version,
    )


# ── the harness ──────────────────────────────────────────────────────────────
async def _run(attacks: int, real_db_path: Path) -> LoadTestResult:
    # Redirect the data dir to a fresh temp dir BEFORE building Settings so the
    # run's SQLite file can never be the real one.
    tmp_dir = Path(tempfile.mkdtemp(prefix="adversaryforge-loadtest-"))
    os.environ["ADVERSARYFORGE_DATA_DIR"] = str(tmp_dir)
    settings = Settings()  # constructed fresh (not the lru_cached get_settings)

    # Hard safety assertion: the resolved db path must live under the temp dir.
    db_path = settings.db_path
    assert Path(db_path).resolve().is_relative_to(tmp_dir.resolve()), (
        f"refusing to run: settings.db_path {db_path} is not inside temp {tmp_dir}"
    )

    real_before = _db_stat(real_db_path)

    adapter = agentforge_adapter(settings.target_base_url)
    session = build_session(settings)  # Anonymous unless a cookie is configured
    store = Store(db_path)
    library = SeedLibrary.load()
    # Deterministic-first: no LLM adjudicator, so this runs with no API key.
    judge = Judge(llm_adjudicator=None)

    runnable = library.runnable(authenticated=False)
    if not runnable:
        raise RuntimeError("no unauthenticated seeds to load-test with")

    exec_ms: list[float] = []
    judge_ms: list[float] = []
    storage_ms: list[float] = []
    target_single_ms: list[float] = []
    burst_ms: list[float] = []
    outcomes: dict[str, int] = {}
    store_write_ops = 0
    exploits_stored = 0
    total_storage_s = 0.0

    tracemalloc.start()
    wall0 = time.perf_counter()

    async with TargetClient(adapter, session, settings) as client:
        # Establish target version once (also a live liveness check).
        vresp = await client.request("GET", "/health")
        vj = vresp.json
        version = str(vj["version"]) if isinstance(vj, dict) and vj.get("version") else "unknown"
        run_id = store.start_run(settings.target_base_url, version,
                                 "unauthenticated", False,
                                 notes=f"loadtest attacks={attacks}")
        executor = SeedExecutor(client)
        directive_id = "dir_loadtest"

        for i in range(attacks):
            seed: Seed = runnable[i % len(runnable)]

            t0 = time.perf_counter()
            attempt = await executor.run(seed, directive_id)
            t1 = time.perf_counter()
            exec_ms.append((t1 - t0) * 1000)

            singles, bursts = _target_latencies(attempt)
            target_single_ms.extend(singles)
            burst_ms.extend(bursts)

            s0 = time.perf_counter()
            store.record_attempt(run_id, attempt)
            store_write_ops += 1
            s1 = time.perf_counter()

            j0 = time.perf_counter()
            verdict = judge.evaluate_attempt(attempt)
            j1 = time.perf_counter()
            judge_ms.append((j1 - j0) * 1000)

            s2 = time.perf_counter()
            store.record_verdict(run_id, verdict)
            store_write_ops += 1
            out = verdict.outcome.value if hasattr(verdict.outcome, "value") else str(verdict.outcome)
            outcomes[out] = outcomes.get(out, 0) + 1
            if verdict.outcome == Outcome.success:
                inserted = store.record_exploit(_build_exploit(attempt, verdict, version))
                store_write_ops += 1
                if inserted:
                    exploits_stored += 1
            s3 = time.perf_counter()

            storage_this = (s1 - s0) + (s3 - s2)
            storage_ms.append(storage_this * 1000)
            total_storage_s += storage_this

        store.end_run(run_id, 0.0)

    wall = time.perf_counter() - wall0
    traced_peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    store.close()

    real_after = _db_stat(real_db_path)

    if resource is not None:
        ru_maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # macOS reports ru_maxrss in bytes; Linux in kilobytes.
        peak_rss_mb = (ru_maxrss / (1024 * 1024)) if sys.platform == "darwin" else (ru_maxrss / 1024)
    else:  # non-POSIX (Windows): getrusage unavailable
        peak_rss_mb = 0.0

    return LoadTestResult(
        attacks_total=attacks,
        wall_seconds=round(wall, 3),
        throughput_attacks_per_s=round(attacks / wall, 3) if wall > 0 else 0.0,
        target_url=settings.target_base_url,
        target_version=version,
        authenticated=session.is_authenticated,
        max_concurrency=settings.max_concurrency,
        min_request_gap_s=settings.min_request_gap_s,
        request_timeout_s=settings.request_timeout_s,
        execution=Phase.of("execution", exec_ms),
        target_http=Phase.of("target_http", target_single_ms),
        judge=Phase.of("judge", judge_ms),
        storage=Phase.of("storage", storage_ms),
        burst_http=Phase.of("burst_http", burst_ms),
        store_write_ops=store_write_ops,
        storage_writes_per_s=round(store_write_ops / total_storage_s, 1) if total_storage_s > 0 else 0.0,
        exploits_stored=exploits_stored,
        outcomes=outcomes,
        peak_traced_mem_mb=round(traced_peak / (1024 * 1024), 2),
        peak_rss_mb=round(peak_rss_mb, 1),
        python_version=sys.version.split()[0],
        platform=sys.platform,
        seeds_cycled=len(runnable),
        temp_db_path=str(db_path),
        real_db_untouched=(real_before == real_after),
        real_db_before=real_before,
        real_db_after=real_after,
    )


def run_loadtest(attacks: int = 100, *, real_db_path: Path | str | None = None) -> LoadTestResult:
    """Run the load test synchronously and return the captured metrics.

    ``attacks`` is the number of attack executions (unauthenticated seeds cycled).
    ``real_db_path`` is the production DB whose immutability we assert; it defaults
    to the repo's ``data/adversaryforge.sqlite`` (resolved without importing the
    real settings, so pointing DATA_DIR at the temp dir does not hide it).
    """
    if real_db_path is None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        real_db_path = repo_root / "data" / "adversaryforge.sqlite"
    return asyncio.run(_run(attacks, Path(real_db_path)))
