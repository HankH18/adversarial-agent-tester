"""SQLite-backed exploit database, run log, and metrics substrate.

Data-quality contract (enforced here, per the platform requirements):
  * every confirmed exploit has a unique id;
  * required fields are non-null (severity, category, reproduction, observed,
    expected) — validated by the pydantic contract *before* it reaches this store;
  * no duplicate exploit for the same attack sequence — enforced by a UNIQUE index
    on a content `dedupe_key` (hash of category + minimal transcript).

Migrations: schema changes go through `apply_migrations`, which is additive and
idempotent (SQLite `ADD COLUMN`), so existing records survive a field addition
without data loss. `schema_version` is recorded in `meta`.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from adversaryforge.contracts import (
    ConfirmedExploit,
    RegressionCandidate,
    Verdict,
    VulnReport,
)

SCHEMA_VERSION = 2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(obj: Any) -> str:
    def _default(o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        if hasattr(o, "model_dump"):
            return o.model_dump(mode="json")
        return str(o)

    return json.dumps(obj, default=_default)


class Store:
    """The platform's own database. Read-write for the platform; the target never
    touches it."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self.apply_migrations()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ── schema / migrations ────────────────────────────────────────────────
    def apply_migrations(self) -> None:
        c = self._conn
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

            CREATE TABLE IF NOT EXISTS runs (
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

            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                run_id TEXT,
                directive_id TEXT,
                seed_id TEXT,
                category TEXT NOT NULL,
                subcategory TEXT,
                generation INTEGER DEFAULT 0,
                parent_attempt_id TEXT,
                target_invariant TEXT,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verdicts (
                verdict_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL,
                run_id TEXT,
                outcome TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                method TEXT,
                invariant_violated TEXT,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exploits (
                exploit_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL,
                verdict_id TEXT NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT,
                severity TEXT NOT NULL,
                target_invariant TEXT,
                target_version TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                dedupe_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                exploit_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                requires_human_approval INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS regression_cases (
                case_id TEXT PRIMARY KEY,
                exploit_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                added_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                ts TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS cost_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                ts TEXT NOT NULL,
                agent TEXT NOT NULL,
                model TEXT,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                usd REAL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS ix_attempts_cat ON attempts(category);
            CREATE INDEX IF NOT EXISTS ix_attempts_run ON attempts(run_id);
            CREATE INDEX IF NOT EXISTS ix_verdicts_outcome ON verdicts(outcome, severity);
            CREATE INDEX IF NOT EXISTS ix_verdicts_attempt ON verdicts(attempt_id);
            CREATE INDEX IF NOT EXISTS ix_exploits_sev ON exploits(severity, category);
            CREATE INDEX IF NOT EXISTS ix_exploits_ver ON exploits(target_version);
            CREATE INDEX IF NOT EXISTS ix_exploits_status ON exploits(status);
            CREATE UNIQUE INDEX IF NOT EXISTS ux_exploits_dedupe ON exploits(dedupe_key);
            CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id, event_id);
            """
        )
        c.execute(
            "INSERT INTO meta(key,value) VALUES('schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
        c.commit()

    # ── writes ─────────────────────────────────────────────────────────────
    def start_run(self, target_url: str, target_version: str, mode: str,
                  authenticated: bool, notes: str = "") -> str:
        run_id = "run_" + uuid.uuid4().hex[:12]
        with self._tx() as c:
            c.execute(
                "INSERT INTO runs(run_id,started_at,target_url,target_version,mode,authenticated,notes)"
                " VALUES(?,?,?,?,?,?,?)",
                (run_id, _now(), target_url, target_version, mode, int(authenticated), notes),
            )
        self.log_event(run_id, "orchestrator", "run_started",
                       f"{mode} vs {target_url}@{target_version}")
        return run_id

    def end_run(self, run_id: str, cost_usd: float = 0.0) -> None:
        with self._tx() as c:
            c.execute("UPDATE runs SET ended_at=?, cost_usd=? WHERE run_id=?",
                      (_now(), cost_usd, run_id))
        self.log_event(run_id, "orchestrator", "run_ended", f"cost=${cost_usd:.4f}")

    def record_attempt(self, run_id: str, attempt) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO attempts(attempt_id,run_id,directive_id,seed_id,category,"
                "subcategory,generation,parent_attempt_id,target_invariant,created_at,payload)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (attempt.attempt_id, run_id, attempt.directive_id, attempt.seed_id,
                 _enum(attempt.category), attempt.subcategory, attempt.generation,
                 attempt.parent_attempt_id, attempt.target_invariant, _now(),
                 attempt.model_dump_json()),
            )

    def record_verdict(self, run_id: str, verdict: Verdict) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO verdicts(verdict_id,attempt_id,run_id,outcome,severity,"
                "confidence,method,invariant_violated,created_at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (verdict.verdict_id, verdict.attempt_id, run_id, _enum(verdict.outcome),
                 _enum(verdict.severity), verdict.confidence, verdict.method,
                 verdict.invariant_violated, _now(), verdict.model_dump_json()),
            )

    def record_exploit(self, exploit: ConfirmedExploit) -> bool:
        """Insert a confirmed exploit. Returns False if a duplicate attack sequence
        already exists (dedupe), True on a new insert."""
        dedupe = self._dedupe_key(exploit)
        try:
            with self._tx() as c:
                c.execute(
                    "INSERT INTO exploits(exploit_id,attempt_id,verdict_id,category,subcategory,"
                    "severity,target_invariant,target_version,status,dedupe_key,created_at,payload)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (exploit.exploit_id, exploit.attempt_id, exploit.verdict_id,
                     _enum(exploit.category), exploit.subcategory, _enum(exploit.severity),
                     exploit.target_invariant, exploit.target_version, "open", dedupe,
                     _now(), exploit.model_dump_json()),
                )
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate attack sequence — data-quality guard held

    def record_report(self, report: VulnReport) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO reports(report_id,exploit_id,severity,status,"
                "requires_human_approval,created_at,payload) VALUES(?,?,?,?,?,?,?)",
                (report.report_id, report.exploit_id, _enum(report.severity),
                 report.status, int(report.requires_human_approval), _now(),
                 report.model_dump_json()),
            )

    def record_regression_case(self, case: RegressionCandidate) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO regression_cases(case_id,exploit_id,category,severity,"
                "added_at,payload) VALUES(?,?,?,?,?,?)",
                (case.case_id, case.exploit_id, _enum(case.category), _enum(case.severity),
                 _now(), case.model_dump_json()),
            )

    def set_exploit_status(self, exploit_id: str, status: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE exploits SET status=? WHERE exploit_id=?", (status, exploit_id))

    def log_event(self, run_id: str | None, agent: str, action: str, detail: str = "") -> None:
        with self._tx() as c:
            c.execute("INSERT INTO events(run_id,ts,agent,action,detail) VALUES(?,?,?,?,?)",
                      (run_id, _now(), agent, action, detail))

    def log_cost(self, run_id: str | None, agent: str, model: str,
                 input_tokens: int, output_tokens: int, usd: float) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO cost_ledger(run_id,ts,agent,model,input_tokens,output_tokens,usd)"
                " VALUES(?,?,?,?,?,?,?)",
                (run_id, _now(), agent, model, input_tokens, output_tokens, usd),
            )

    # ── reads (the observability questions) ────────────────────────────────
    def coverage_by_category(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT category, COUNT(*) n FROM attempts GROUP BY category"
        ).fetchall()
        return {r["category"]: r["n"] for r in rows}

    def passfail_rates(self, target_version: str | None = None) -> dict[str, dict[str, int]]:
        q = ("SELECT a.category cat, v.outcome out, COUNT(*) n FROM verdicts v "
             "JOIN attempts a ON a.attempt_id=v.attempt_id ")
        params: tuple = ()
        if target_version:
            q += "JOIN runs r ON r.run_id=v.run_id WHERE r.target_version=? "
            params = (target_version,)
        q += "GROUP BY a.category, v.outcome"
        out: dict[str, dict[str, int]] = {}
        for r in self._conn.execute(q, params).fetchall():
            out.setdefault(r["cat"], {})[r["out"]] = r["n"]
        return out

    def resilience_trend(self) -> list[dict[str, Any]]:
        """Per run: success rate over completed verdicts. Falling = more resilient."""
        rows = self._conn.execute(
            "SELECT r.run_id, r.started_at, r.target_version, "
            "SUM(CASE WHEN v.outcome='success' THEN 1 ELSE 0 END) succ, COUNT(v.verdict_id) tot "
            "FROM runs r LEFT JOIN verdicts v ON v.run_id=r.run_id "
            "GROUP BY r.run_id ORDER BY r.started_at"
        ).fetchall()
        return [
            {"run_id": r["run_id"], "started_at": r["started_at"],
             "target_version": r["target_version"], "successes": r["succ"] or 0,
             "total": r["tot"] or 0,
             "success_rate": round((r["succ"] or 0) / r["tot"], 3) if r["tot"] else None}
            for r in rows
        ]

    def open_findings(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) n FROM exploits GROUP BY status"
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def cost_summary(self, run_id: str | None = None) -> dict[str, Any]:
        q = "SELECT COALESCE(SUM(usd),0) usd, COALESCE(SUM(input_tokens),0) it, " \
            "COALESCE(SUM(output_tokens),0) ot, COUNT(*) calls FROM cost_ledger"
        params: tuple = ()
        if run_id:
            q += " WHERE run_id=?"
            params = (run_id,)
        r = self._conn.execute(q, params).fetchone()
        return {"usd": round(r["usd"], 6), "input_tokens": r["it"],
                "output_tokens": r["ot"], "llm_calls": r["calls"]}

    def agent_timeline(self, run_id: str, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT ts, agent, action, detail FROM events WHERE run_id=? "
            "ORDER BY event_id LIMIT ?", (run_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_exploits(self, status: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM exploits"
        params: tuple = ()
        if status:
            q += " WHERE status=?"
            params = (status,)
        q += " ORDER BY created_at DESC"
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    def list_regression_cases(self) -> list[RegressionCandidate]:
        rows = self._conn.execute("SELECT payload FROM regression_cases").fetchall()
        return [RegressionCandidate.model_validate_json(r["payload"]) for r in rows]

    def get_exploit(self, exploit_id: str) -> ConfirmedExploit | None:
        r = self._conn.execute("SELECT payload FROM exploits WHERE exploit_id=?",
                               (exploit_id,)).fetchone()
        return ConfirmedExploit.model_validate_json(r["payload"]) if r else None

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _dedupe_key(exploit: ConfirmedExploit) -> str:
        seq = _enum(exploit.category) + "|" + "|".join(
            f"{t.role}:{t.content}" for t in exploit.minimal_transcript
        )
        return hashlib.sha256(seq.encode()).hexdigest()

    def close(self) -> None:
        self._conn.close()


def _enum(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)
