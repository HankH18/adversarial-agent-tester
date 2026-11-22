# AdversaryForge — Performance Baseline

> **Historical measurement.** These numbers were measured in July 2026 against the deployment at
> `agentforge.hankholcomb.com`, which is offline today. Reproducing them needs a running target
> (set `ADVERSARYFORGE_TARGET_BASE_URL`).

A load/baseline measurement of the multi-agent attack pipeline running against the
**live** target. It answers "how fast is the platform, where does the time go, and
what would we change to go faster" with numbers we actually measured — not
estimates.

Per the spec's representative-run requirement (p12: *"100 attack cases, full
regression suite"* and record *"agent orchestration latency, LLM call latency,
exploit storage throughput"*), the representative run captures three things end to
end in a single isolated run:

1. **100 attack executions** against the live target (the load/throughput profile).
2. The **full regression suite** — every case the run promotes is replayed by the
   platform's own `harness.run_regression`, so the regression harness's own
   performance is baselined too, not just attack execution.
3. **LLM-call latency** — a *bounded, key-gated* sample of real Judge LLM-adjudicator
   completions (see the LLM row below). The keyless representative run records this
   phase with `n=0` by design; the digits are filled from a small keyed sample.

## How to reproduce

```bash
.venv/bin/python scripts/run_loadtest.py 100        # human-readable report
.venv/bin/python scripts/run_loadtest.py 100 --json # machine-readable (the JSON
                                                    # carries the regression-suite
                                                    # and LLM-call-latency fields)
```

To populate the **LLM-call-latency** row, run a small keyed sample (this makes real,
billed API calls — keep the sample small):

```python
# with ANTHROPIC_API_KEY set in the environment
from adversaryforge.perf import run_loadtest
r = run_loadtest(100, llm_probe_samples=3)   # times 3 real adjudicator completions
print(r.llm_call_latency)                    # p50/p95/max/mean/n
```

Harness: `adversaryforge/perf/loadtest.py`. It cycles the **10 unauthenticated
seeds** (`evals/seeds/unauthenticated.yaml`) — cheap endpoints only (e.g. `/health`,
`/ready`, `/openapi.json`, `/v1/auth/status`, `/v1/auth/me`, an anonymous `/v1/chat`,
and one bounded 12-request burst to `/health`). The platform's **self-throttle stays
ON** (`max_concurrency=2`, `min_request_gap_s=0.5`) so the harness cannot become a
DoS against a system physicians depend on. The 100-attack loop runs
deterministic-first: **no LLM key**, no per-attack LLM adjudicator — every verdict in
the loop is pure code. (The LLM-call-latency phase is timed *outside* that loop, from
a bounded key-gated sample, precisely so the load run never fires 100 LLM calls.)

**Isolation guarantee.** Before any `Settings` is built, `ADVERSARYFORGE_DATA_DIR`
is redirected to a fresh `tempfile.mkdtemp` directory, and the harness asserts the
resolved `db_path` lives inside it. Both the 100-attack loop *and* the regression
suite resolve their `Store`/`TargetClient` from that same temp `Settings`, so the
real `data/adversaryforge.sqlite` is never touched by either. The harness records the
real DB's size+mtime before and after and reports whether it changed. In the run
below it was **untouched** (identical size and mtime ns).

## Environment / context

| | |
|---|---|
| Host | Apple Silicon (macOS, `darwin`) |
| Python | 3.12.13 |
| Target | `https://agentforge.hankholcomb.com` (version `0.1.0`, unauthenticated) |
| Network | public internet → live deploy (real RTT, not localhost) |
| Self-throttle | `max_concurrency=2`, `min_request_gap_s=0.5`, `request_timeout_s=30.0` |
| Judge (load loop) | deterministic (no LLM key) |
| LLM-call-latency sample | key-gated; keyless run here → `n=0` (see TODO below) |
| Seeds | 10 unauthenticated, cycled to 100 attack executions |
| Regression suite | full suite replayed after the 100 attacks (all promoted cases) |

## Measured baseline — 100 attack executions + full regression suite

| Metric | Value |
|---|---|
| Attacks executed | 100 |
| Wall clock (100-attack loop) | **60.003 s** |
| Throughput | **1.667 attacks/sec** |
| Outcomes (judge classification*) | failure 50, success 50 |
| Exploits stored (deduped) | 5 |
| Regression cases replayed | 5 |
| Regression suite wall clock | **3.774 s** (1.325 cases/sec) |

\* *These outcome labels are the deterministic judge's classification of the
unauthenticated probe responses. They are incidental to the performance
measurement — the perf harness deliberately reuses the real judge + store path; it
is not itself a security assessment. See `THREAT_MODEL.md` / `LIVE_FINDINGS.md` for
what is and isn't a confirmed vulnerability.*

### Per-phase latency (ms)

| Phase | p50 | p95 | max | mean | n |
|---|---:|---:|---:|---:|---:|
| **Execution / attack** (`SeedExecutor.run`: compile → throttled HTTP → transcript) | 498.31 | 2240.04 | 3202.13 | 595.38 | 100 |
| **Target HTTP** (`TargetResponse.latency_ms`, single requests) | 58.14 | 1809.57 | 2764.99 | 275.53 | 90 |
| **Judge overhead** (`Judge.evaluate_attempt`, deterministic) | 0.37 | 0.54 | 0.71 | 0.36 | 100 |
| **Storage / attack** (`record_attempt` + `record_verdict` [+ `record_exploit`/`record_regression_case`]) | 1.56 | 2.78 | 3.78 | 1.57 | 100 |
| **Burst** (12-way concurrent `/health`, aggregate elapsed) | 237.07 | 273.03 | 273.49 | 243.00 | 10 |
| **LLM-call latency** (Judge LLM-adjudicator completion; key-gated bounded sample) | 1872.19 | 2389.41 | 2446.88 | 2035.40 | 3 |

> **LLM-call latency** was captured on **2026-07-24** from a bounded **keyed** sample of 3
> real `make_llm_adjudicator` (Claude Opus) completions (`ANTHROPIC_API_KEY` set,
> `run_loadtest(15, llm_probe_samples=3)`). At ~1.9–2.4 s per adjudication it is **~3-4
> orders of magnitude slower than the deterministic Judge tier (0.37 ms)** — which is why
> the platform is deterministic-first and reserves the LLM tier for the few ambiguous
> verdicts. The 100-attack representative loop stays keyless by design so it never fires
> 100 LLM calls; the latency above is measured out-of-loop on the bounded probe set.

### Regression suite (full suite, replayed after the 100 attacks)

| Metric | Value |
|---|---|
| Cases replayed | 5 |
| Wall clock | **3.774 s** |
| Throughput | **1.325 cases/sec** |
| passed / failed / skipped / errored | 0 / 5 / 0 / 0 |

The suite replays every case the 100-attack run promoted, through the same
self-throttle. All 5 "failed" (i.e. reproduced) because they are replayed against the
**same unchanged target version** they were just promoted from — so they reproduce by
construction. That is the expected result for a within-run baseline: the number that
matters here is the harness's **throughput** (~1.3 cases/sec, again throttle-bound),
not the pass/fail (a real regression run happens across target *versions*, where a
PASS means a previously confirmed exploit no longer reproduces).

### Storage throughput

| Metric | Value |
|---|---|
| Store write ops (100-attack loop) | 255 |
| Writes/sec (over storage time only) | **1,625.7** |
| Exploits stored (unique, after dedupe) | 5 |

### Memory

| Metric | Value |
|---|---|
| Peak traced (tracemalloc, 100-attack loop) | 3.50 MB |
| Peak RSS (`getrusage`, whole process) | 59.8 MB |

## Where the time goes — the bottleneck

**The bottleneck is the throttled network path, not the platform's own agents.**

- **Execution p50 (498 ms) ≈ the 500 ms self-throttle `min_request_gap_s`.** Almost
  the entire per-attack cost is the deliberate inter-request gap the client enforces
  in `_pace()`. Throughput of ~1.7/s is essentially `1 / (0.5 s gap + RTT)` — the
  gap is the ceiling.
- **The platform's own orchestration is effectively free.** The independent Judge
  costs **0.36 ms** mean and the SQLite exploit-store write path costs **1.57 ms**
  mean (~1,626 write-ops/sec). Together the platform-side compute is ~2 ms of a
  ~595 ms attack — well under 0.5% of wall time. The system is I/O-bound on the
  throttled HTTP path.
- **The p95 execution spike (2,240 ms) is the target, not us.** Target HTTP p50 is a
  fast 58 ms (liveness/config endpoints) but p95 is 1,810 ms — driven by the
  anonymous `POST /v1/chat` turn, which does heavier server-side work. That variance
  rides on top of the fixed 500 ms gap.
- **The regression harness is throttle-bound too.** 5 cases in 3.77 s ≈ the same
  `1 / (gap + RTT)` ceiling — the harness adds no meaningful per-case compute of its
  own; it is the same replay-through-the-throttle path.
- **Memory is a non-issue** at this scale: 3.5 MB traced, 60 MB RSS for a 100-attack
  run plus the regression suite.

In short: two terms dominate, in order — **(1) the 500 ms self-throttle min-gap on
every request (by design, a safety choice), and (2) network RTT + target compute,
which spikes on the chat endpoint.** The Judge, Orchestrator, exploit store, and
regression harness are not on the critical path.

## Architectural changes that would address it

The throttle is a *deliberate* safety ceiling against a live clinical system, so the
answer is not "remove the throttle" — it is "give the platform a faster lane for the
work that does not need to touch the shared live deploy."

1. **Run high-volume passes against a LOCAL target in `auth_mode=disabled`.** The
   adapter already infers `disabled` mode for a `localhost`/`127.0.0.1` base URL
   (`agentforge_adapter`). Against a local OpenEMR co-pilot, both dominant terms
   vanish: the network RTT term (target HTTP p95 was 1.8 s) and the safety-imposed
   500 ms gap can both be dropped, because we are no longer sharing a production
   deploy. This is the right home for large regression/fuzz volume; the live deploy
   run stays throttled for authenticity/evidence.

2. **Actually exploit `max_concurrency`, and tune the gap within safe limits.** The
   client holds a `Semaphore(max_concurrency=2)`, but this harness (and the campaign
   loop) `await` attacks sequentially, so the concurrency budget is never used — and
   even if it were, `_pace()` serializes *request starts* behind `min_request_gap_s`,
   so start rate is still capped at `1/0.5 = 2/s`. To exceed 2/s you must lower
   `min_request_gap_s`; to benefit from concurrency you must dispatch up to
   `max_concurrency` attacks in flight (a bounded producer/consumer pool). Against a
   target that can absorb it (a local instance, or the live deploy with the operator's
   explicit sign-off on a higher rate), lowering the gap to e.g. 0.1 s and running a
   concurrency-2 pool would move the ceiling from ~1.7/s toward ~10-20/s.

3. **Do NOT bother pipelining Judge/storage.** A natural instinct is to overlap
   adjudication and DB writes with the next request. The measurements say don't:
   Judge is 0.36 ms and storage is 1.57 ms per attack. Pipelining them would recover
   under 0.5% of wall time. The engineering effort belongs entirely on the network
   term (#1, #2), not on the platform's own compute.

### Bottom line

At the current safe live-deploy settings the platform sustains **~1.7 attacks/sec**
and **~1.3 regression-cases/sec**, gated almost entirely by the 500 ms self-throttle
and live-target RTT. The multi-agent machinery itself (independent Judge + SQLite
exploit store + regression harness) adds ~2 ms per attack and ~1,626 store-writes/sec
of headroom — it is nowhere near the limit. Volume scaling should come from a local
`auth_mode=disabled` target and/or an operator-approved concurrency/gap change, never
from removing the live-deploy safety throttle.
