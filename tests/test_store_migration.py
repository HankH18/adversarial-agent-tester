"""Schema auto-migration + burn-rate query — the two data-substrate guarantees the
platform makes but the store previously only *claimed*.

Migration (spec): "the exploit DB schema must support migration — if you add a field,
existing records must be migrated without data loss." Before the fix, SCHEMA_VERSION
was written but never read to branch, and apply_migrations only did CREATE TABLE ...
IF NOT EXISTS — so a pre-existing older-shaped DB kept its old columns and silently
missed new ones. These tests build an older-shaped DB, open it with the current Store,
and prove the new column appears AND every old row survives.

Burn rate (spec observability Q5): "how much did this run cost, and AT WHAT RATE is
cost scaling?" cost_summary/cost_by_agent give only totals; Store.cost_rate adds the
rate (USD/hour) and the cross-run scaling slope. These tests prove the numbers.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adversaryforge.contracts import (
    AttackCategory,
    ConfirmedExploit,
    Severity,
    TranscriptTurn,
)
from adversaryforge.observability.store import SCHEMA_VERSION, Store, _linreg_slope

# The exact `runs` DDL as it stood at schema v3 — deliberately WITHOUT the v4
# `finding_count` column. This is the "older-shaped DB" the migration must upgrade.
_V3_RUNS_DDL = """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        target_url TEXT,
        target_version TEXT,
        mode TEXT,
        authenticated INTEGER DEFAULT 0,
        cost_usd REAL DEFAULT 0,
        notes TEXT
    );
"""


def _build_old_v3_db(path: Path, rows: list[tuple]) -> None:
    """Hand-build a pre-existing v3-shaped DB (no `finding_count`), stamped at
    schema_version 3, with the given `runs` rows. Written with a raw connection so it
    is NOT auto-migrated until the current Store opens it."""
    conn = sqlite3.connect(path)
    conn.executescript(_V3_RUNS_DDL)
    conn.executemany(
        "INSERT INTO runs(run_id,started_at,target_url,target_version,mode,"
        "authenticated,cost_usd,notes) VALUES(?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.execute("INSERT INTO meta(key,value) VALUES('schema_version','3')")
    conn.commit()
    conn.close()


def _table_columns(store: Store, table: str) -> set[str]:
    return {r[1] for r in store._conn.execute(f"PRAGMA table_info({table})").fetchall()}


# ── (1) real schema auto-migration ──────────────────────────────────────────
def test_reproduce_gap_current_code_never_patches_a_missing_column():
    """The gap, isolated: `apply_migrations` runs CREATE TABLE IF NOT EXISTS against an
    already-existing table, which is a no-op — so a table missing a current column stays
    missing until a *versioned ALTER step* runs. Proven by stamping the DB at the CURRENT
    version (so the version gate skips every migration step) and confirming the missing
    column is NOT added."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "gap.sqlite"
        conn = sqlite3.connect(path)
        conn.executescript(_V3_RUNS_DDL)  # runs table missing `finding_count`
        conn.execute("INSERT INTO runs(run_id,started_at,mode) VALUES('r','t','test')")
        # Stamp at CURRENT version → version gate believes it is up to date → no step runs.
        conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?)",
                     (str(SCHEMA_VERSION),))
        conn.commit()
        conn.close()

        store = Store(path)
        # CREATE TABLE IF NOT EXISTS did NOT retrofit the column: the gap is real.
        assert "finding_count" not in _table_columns(store, "runs")
        store.close()


def test_old_v3_db_migrates_adds_column_and_preserves_all_rows():
    """The mandated proof: an older-shaped DB, opened by the current Store, gains the new
    column and loses no data."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "old.sqlite"
        rows = [
            ("run_a", "2026-01-01T00:00:00+00:00", "http://t", "v1", "campaign", 1, 0.42, "first"),
            ("run_b", "2026-01-02T00:00:00+00:00", "http://t", "v2", "regression", 0, 0.0, "second"),
            ("run_c", "2026-01-03T00:00:00+00:00", "http://t", "v2", "demo", 1, 1.5, "third"),
        ]
        _build_old_v3_db(path, rows)

        store = Store(path)

        # (a) the new column/shape exists after opening with the current Store.
        assert "finding_count" in _table_columns(store, "runs")

        # (b) every old row survived intact — no data loss across all fields.
        got = {r["run_id"]: dict(r) for r in
               store._conn.execute("SELECT * FROM runs ORDER BY started_at").fetchall()}
        assert set(got) == {"run_a", "run_b", "run_c"}
        assert got["run_a"]["target_version"] == "v1"
        assert got["run_a"]["cost_usd"] == 0.42
        assert got["run_a"]["notes"] == "first"
        assert got["run_a"]["authenticated"] == 1
        assert got["run_b"]["mode"] == "regression"
        assert got["run_c"]["cost_usd"] == 1.5
        # backfilled to 0 for runs that have no confirmed exploits (correct).
        assert all(r["finding_count"] == 0 for r in got.values())

        # the version was stamped forward in BOTH meta and PRAGMA user_version.
        mv = store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"]
        uv = store._conn.execute("PRAGMA user_version").fetchone()[0]
        assert mv == str(SCHEMA_VERSION)
        assert uv == SCHEMA_VERSION
        store.close()


def test_migration_backfills_finding_count_from_existing_exploits():
    """The v4 step is a real ALTER + *backfill*, not just a defaulted column: it
    recomputes finding_count from confirmed exploits (joined via attempts). Proven by
    populating a full v4 DB, stamping it back to v3 with a deliberately-wrong count, and
    reopening — the migration must overwrite the wrong count with the true one and keep
    the exploit data."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "backfill.sqlite"
        store = Store(path)
        rid = store.start_run("http://t", "v", "campaign", False)
        # An attempt owned by this run, and a confirmed exploit pointing at it.
        store._conn.execute(
            "INSERT INTO attempts(attempt_id,run_id,category,created_at,payload) "
            "VALUES(?,?,?,?,?)",
            ("at1", rid, "data_exfiltration", "2026-01-01T00:00:00+00:00", "{}"),
        )
        store._conn.commit()
        assert store.record_exploit(ConfirmedExploit(
            exploit_id="ex1", attempt_id="at1", verdict_id="vd1",
            category=AttackCategory.data_exfiltration, severity=Severity.high,
            target_invariant="INV-AUTHZ-PATIENT",
            minimal_transcript=[TranscriptTurn(role="attacker", content="probe")],
            expected_safe="403", observed="leak")) is True

        # Simulate a real pre-v4 DB that already holds exploit data: wrong count + old stamp.
        store._conn.execute("UPDATE runs SET finding_count=999 WHERE run_id=?", (rid,))
        store._conn.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
        store._conn.execute("PRAGMA user_version = 0")
        store._conn.commit()
        store.close()

        store2 = Store(path)  # reopen → v3→v4 step runs and backfills
        run = store2.get_run(rid)
        assert run["finding_count"] == 1        # backfilled from the 1 exploit (not 999, not 0)
        assert len(store2.list_exploits()) == 1  # exploit data preserved through migration
        store2.close()


def test_fresh_db_is_stamped_current_with_new_column():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        store = Store(Path(d) / "fresh.sqlite")
        assert "finding_count" in _table_columns(store, "runs")
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"] \
            == str(SCHEMA_VERSION)
        store.close()


def test_reopening_up_to_date_db_is_a_noop_and_keeps_data():
    """Idempotency: reopening an already-current DB runs no migration steps and preserves
    everything written to it."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "reopen.sqlite"
        store = Store(path)
        rid = store.start_run("http://t", "v", "campaign", False, notes="keep me")
        store.close()

        store2 = Store(path)
        assert store2._conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        run = store2.get_run(rid)
        assert run is not None and run["notes"] == "keep me"
        store2.close()


# ── (2) burn-rate query ──────────────────────────────────────────────────────
def _ledger(store: Store, run_id: str, ts: str, usd: float) -> None:
    store._conn.execute(
        "INSERT INTO cost_ledger(run_id,ts,agent,model,input_tokens,output_tokens,usd) "
        "VALUES(?,?,?,?,?,?,?)", (run_id, ts, "redteam", "m", 0, 0, usd))
    store._conn.commit()


def test_cost_rate_computes_burn_rate_over_the_ledger_window(tmp_path):
    """USD/hour = total spend / elapsed cost-ledger window. Two $1 calls one hour apart
    → $2 over 1h → $2/hour."""
    store = Store(tmp_path / "rate.sqlite")
    rid = store.start_run("http://t", "v", "campaign", False)
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    _ledger(store, rid, t0.isoformat(), 1.0)
    _ledger(store, rid, (t0 + timedelta(hours=1)).isoformat(), 1.0)

    r = store.cost_rate(rid)
    assert r["total_usd"] == 2.0
    assert r["llm_calls"] == 2
    assert r["elapsed_seconds"] == 3600.0
    assert r["usd_per_hour"] == 2.0          # the RATE, not just the total
    assert r["usd_per_call"] == 1.0
    store.close()


def test_cost_rate_detects_rising_cross_run_scaling(tmp_path):
    """"At what rate is cost scaling?" — across three runs costing $1, $2, $3 the per-run
    slope is +$1/run and the trend reads 'rising'."""
    store = Store(tmp_path / "scale.sqlite")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i, cost in enumerate((1.0, 2.0, 3.0)):
        rid = f"run_{i}"
        store._conn.execute(
            "INSERT INTO runs(run_id,started_at,mode) VALUES(?,?,?)",
            (rid, (base + timedelta(minutes=i)).isoformat(), "campaign"))
        store._conn.commit()
        _ledger(store, rid, (base + timedelta(minutes=i)).isoformat(), cost)

    r = store.cost_rate()  # platform-wide cross-run trend
    assert [p["usd"] for p in r["per_run"]] == [1.0, 2.0, 3.0]  # oldest → newest
    assert r["usd_per_run_slope"] == 1.0
    assert r["trend"] == "rising"
    store.close()


def test_cost_rate_on_empty_store_is_safe(tmp_path):
    store = Store(tmp_path / "empty.sqlite")
    r = store.cost_rate()
    assert r["total_usd"] == 0.0
    assert r["usd_per_hour"] is None         # no window → no rate, not a crash
    assert r["usd_per_call"] is None
    assert r["trend"] == "flat"
    store.close()


def test_linreg_slope_edges():
    assert _linreg_slope([]) is None
    assert _linreg_slope([5.0]) is None           # one point → no line
    assert _linreg_slope([2.0, 2.0, 2.0]) == 0.0  # flat
    assert _linreg_slope([3.0, 1.0]) == -2.0      # falling
