# AdversaryForge — Performance Baseline

A load/baseline measurement of the multi-agent attack pipeline running against the
**live** target. It answers "how fast is the platform, where does the time go, and
what would we change to go faster" with numbers we actually measured — not
estimates.

## How to reproduce

```bash
.venv/bin/python scripts/run_loadtest.py 100        # human-readable report
.venv/bin/python scripts/run_loadtest.py 100 --json # machine-readable
```

Harness: `adversaryforge/perf/loadtest.py`. It cycles the **8 unauthenticated
seeds** (`evals/seeds/unauthenticated.yaml`) — cheap endpoints only: `/health`,
`/ready`, `/openapi.json`, `/v1/auth/status`, `/v1/auth/me`, `/v1/conversations/1`,
`/v1/patients/1/observations`, an anonymous `/v1/chat`, and one bounded 12-request
burst to `/health`. The platform's **self-throttle stays ON** (`max_concurrency=2`,
`min_request_gap_s=0.5`) so the harness cannot become a DoS against a system
physicians depend on. It runs deterministic-first: **no ANTHROPIC_API_KEY**, no LLM
adjudicator — every verdict here is pure code.

**Isolation guarantee.** Before any `Settings` is built, `ADVERSARYFORGE_DATA_DIR`
is redirected to a fresh `tempfile.mkdtemp` directory, and the harness asserts the
resolved `db_path` lives inside it. It records the real DB's size+mtime before and
after and reports whether it changed. In the run below the real
`data/adversaryforge.sqlite` was **untouched** (identical size and mtime ns).

## Environment / context

| | |
|---|---|
| Host | Apple Silicon (macOS, `darwin`) |
| Python | 3.12.13 |
| Target | `https://agentforge.hankholcomb.com` (version `0.1.0`, unauthenticated) |
| Network | public internet → live deploy (real RTT, not localhost) |
| Self-throttle | `max_concurrency=2`, `min_request_gap_s=0.5`, `request_timeout_s=30.0` |
| Judge | deterministic (no LLM key) |
| Seeds | 8 unauthenticated, cycled to 100 attack executions |

## Measured baseline — 100 attack executions

| Metric | Value |
|---|---|
| Attacks executed | 100 |
| Wall clock | **55.379 s** |
| Throughput | **1.806 attacks/sec** |
| Outcomes | failure 52, success 36, partial 12 |
| Exploits stored (deduped) | 13 |

### Per-phase latency (ms)

| Phase | p50 | p95 | max | mean | n |
|---|---:|---:|---:|---:|---:|
| **Execution / attack** (`SeedExecutor.run`: compile → throttled HTTP → transcript) | 499.07 | 1870.72 | 2163.98 | 547.95 | 100 |
| **Target HTTP** (`TargetResponse.latency_ms`, single requests) | 51.32 | 1446.35 | 1716.06 | 243.10 | 88 |
| **Judge overhead** (`Judge.evaluate_attempt`) | 0.16 | 0.29 | 0.37 | 0.17 | 100 |
| **Storage / attack** (`record_attempt` + `record_verdict` [+ `record_exploit`]) | 1.01 | 2.35 | 12.24 | 1.33 | 100 |
| **Burst** (12-way concurrent `/health`, aggregate elapsed) | 209.74 | 253.48 | 254.96 | 215.56 | 12 |

### Storage throughput

| Metric | Value |
|---|---|
| Store write ops | 236 |
| Writes/sec (over storage time only) | **1,771.3** |
| Exploits stored (unique, after dedupe) | 13 |

### Memory

| Metric | Value |
|---|---|
| Peak traced (tracemalloc) | 9.11 MB |
| Peak RSS (`getrusage`, whole process) | 68.0 MB |

## Where the time goes — the bottleneck

**The bottleneck is the throttled network path, not the platform's own agents.**

- **Execution p50 (499 ms) ≈ the 500 ms self-throttle `min_request_gap_s`.** Almost
  the entire per-attack cost is the deliberate inter-request gap the client enforces
  in `_pace()`. Throughput of 1.806/s is essentially `1 / (0.5 s gap + RTT)` — the
  gap is the ceiling.
- **The platform's own orchestration is effectively free.** The independent Judge
  costs **0.17 ms** mean and the SQLite exploit-store write path costs **1.33 ms**
  mean (~1,771 write-ops/sec). Together the platform-side compute is ~1.5 ms of a
  ~548 ms attack — well under 0.3% of wall time. The system is 100% I/O-bound on the
  throttled HTTP path.
- **The p95 execution spike (1,871 ms) is the target, not us.** Target HTTP p50 is
  a fast 51 ms (liveness/config endpoints) but p95 is 1,446 ms — driven by the
  anonymous `POST /v1/chat` turn, which does heavier server-side work. That variance
  rides on top of the fixed 500 ms gap.
- **Memory is a non-issue** at this scale: 9 MB traced, 68 MB RSS for a 100-attack
  run.

In short: two terms dominate, in order — **(1) the 500 ms self-throttle min-gap on
every request (by design, a safety choice), and (2) network RTT + target compute,
which spikes on the chat endpoint.** The Judge, Orchestrator, and exploit store are
not on the critical path.

## Architectural changes that would address it

The throttle is a *deliberate* safety ceiling against a live clinical system, so the
answer is not "remove the throttle" — it is "give the platform a faster lane for the
work that does not need to touch the shared live deploy."

1. **Run high-volume passes against a LOCAL target in `auth_mode=disabled`.** The
   adapter already infers `disabled` mode for a `localhost`/`127.0.0.1` base URL
   (`agentforge_adapter`). Against a local OpenEMR co-pilot, both dominant terms
   vanish: the network RTT term (target HTTP p95 was 1.4 s) and the safety-imposed
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
   concurrency-2 pool would move the ceiling from ~1.8/s toward ~10-20/s.

3. **Do NOT bother pipelining Judge/storage.** A natural instinct is to overlap
   adjudication and DB writes with the next request. The measurements say don't:
   Judge is 0.17 ms and storage is 1.33 ms per attack. Pipelining them would recover
   under 0.3% of wall time. The engineering effort belongs entirely on the network
   term (#1, #2), not on the platform's own compute.

### Bottom line

At the current safe live-deploy settings the platform sustains **~1.8 attacks/sec**,
gated almost entirely by the 500 ms self-throttle and live-target RTT. The
multi-agent machinery itself (independent Judge + SQLite exploit store) adds ~1.5 ms
per attack and ~1,771 store-writes/sec of headroom — it is nowhere near the limit.
Volume scaling should come from a local `auth_mode=disabled` target and/or an
operator-approved concurrency/gap change, never from removing the live-deploy
safety throttle.
