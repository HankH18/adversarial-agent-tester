"""SQLite-backed exploit database, run log, and metrics substrate.

Data-quality contract (enforced here, per the platform requirements):
  * every confirmed exploit has a unique id;
  * required fields are non-null (severity, category, reproduction, observed,
    expected) — validated by the pydantic contract *before* it reaches this store;
  * no duplicate exploit for the same attack sequence — enforced by a UNIQUE index
    on a content `dedupe_key` (hash of category + minimal transcript).

Migrations: `apply_migrations` is idempotent — every table and index is created
`IF NOT EXISTS`, so a fresh DB gets the full current schema and re-opening an
up-to-date DB is a no-op; existing rows are never dropped or rewritten. The current
`schema_version` is recorded in `meta`. Adding a field to a model means the fresh
schema includes it; upgrading a *pre-existing older* DB in place would need an
explicit `ALTER TABLE ... ADD COLUMN` step keyed off `schema_version` (the runtime
DB here is disposable/regenerated, so that path is documented rather than shipped).
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

SCHEMA_VERSION = 3


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

            CREATE TABLE IF NOT EXISTS spans (
                span_id TEXT PRIMARY KEY,
                run_id TEXT,
                parent_span_id TEXT,
                seq INTEGER,
                agent TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT DEFAULT 'ok',
                start_ts TEXT NOT NULL,
                end_ts TEXT,
                duration_ms REAL,
                attrs TEXT
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
            CREATE INDEX IF NOT EXISTS ix_spans_run ON spans(run_id, seq);
            CREATE INDEX IF NOT EXISTS ix_spans_parent ON spans(parent_span_id);
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

    def record_span(self, span: dict[str, Any]) -> None:
        """Persist one execution-trace span (see observability.tracing)."""
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO spans(span_id,run_id,parent_span_id,seq,agent,name,"
                "status,start_ts,end_ts,duration_ms,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (span["span_id"], span.get("run_id"), span.get("parent_span_id"),
                 span.get("seq"), span["agent"], span["name"], span.get("status", "ok"),
                 span["start_ts"], span.get("end_ts"), span.get("duration_ms"),
                 _dumps(span.get("attrs", {}))),
            )

    def get_spans(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM spans WHERE run_id=? ORDER BY seq", (run_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["attrs"] = json.loads(d["attrs"]) if d["attrs"] else {}
            except Exception:
                d["attrs"] = {}
            out.append(d)
        return out

    # ── reads (the observability questions) ────────────────────────────────
    def coverage_by_category(self, campaign_only: bool = False) -> dict[str, int]:
        # campaign_only excludes regression-replay runs. The Orchestrator uses it so
        # running `regress` (which writes attempts under a mode='regression' run) does
        # NOT perturb the deterministic, reproducible target selection. `status` leaves
        # it False to show ALL activity.
        if campaign_only:
            q = ("SELECT a.category category, COUNT(*) n FROM attempts a "
                 "JOIN runs r ON r.run_id=a.run_id WHERE r.mode NOT IN ('regression','demo') "
                 "GROUP BY a.category")
        else:
            q = "SELECT category, COUNT(*) n FROM attempts GROUP BY category"
        return {r["category"]: r["n"] for r in self._conn.execute(q).fetchall()}

    def passfail_rates(self, target_version: str | None = None,
                       campaign_only: bool = False) -> dict[str, dict[str, int]]:
        q = ("SELECT a.category cat, v.outcome out, COUNT(*) n FROM verdicts v "
             "JOIN attempts a ON a.attempt_id=v.attempt_id ")
        conds: list[str] = []
        params: list[Any] = []
        if target_version or campaign_only:
            q += "JOIN runs r ON r.run_id=v.run_id "
        if target_version:
            conds.append("r.target_version=?")
            params.append(target_version)
        if campaign_only:
            conds.append("r.mode NOT IN ('regression','demo')")  # replays/demo must not skew selection
        if conds:
            q += "WHERE " + " AND ".join(conds) + " "
        q += "GROUP BY a.category, v.outcome"
        out: dict[str, dict[str, int]] = {}
        for r in self._conn.execute(q, tuple(params)).fetchall():
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

    def cost_by_agent(self, run_id: str | None = None) -> list[dict[str, Any]]:
        """Spend broken down per agent role (redteam / judge / documentation) — answers
        "how much did the Red Team spend vs. the Judge," not just a platform total.
        Reads the same per-agent-tagged cost_ledger rows as cost_summary, GROUP BY agent."""
        q = ("SELECT agent, COALESCE(SUM(usd),0) usd, COALESCE(SUM(input_tokens),0) it, "
             "COALESCE(SUM(output_tokens),0) ot, COUNT(*) calls FROM cost_ledger")
        params: tuple = ()
        if run_id:
            q += " WHERE run_id=?"
            params = (run_id,)
        q += " GROUP BY agent ORDER BY usd DESC"
        return [{"agent": r["agent"], "usd": round(r["usd"], 6), "input_tokens": r["it"],
                 "output_tokens": r["ot"], "llm_calls": r["calls"]}
                for r in self._conn.execute(q, params).fetchall()]

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

    def demo_exploit_ids(self) -> set[str]:
        """exploit_ids whose originating attempt belongs to a `mode='demo'` run. Reports
        are for REAL findings, so the report generator excludes these — and therefore
        never prunes the committed `reports/` just because `seed-demo` populated the DB."""
        rows = self._conn.execute(
            "SELECT e.exploit_id FROM exploits e "
            "JOIN attempts a ON a.attempt_id = e.attempt_id "
            "JOIN runs r ON r.run_id = a.run_id "
            "WHERE r.mode = 'demo'"
        ).fetchall()
        return {r["exploit_id"] for r in rows}

    def list_regression_cases(self) -> list[RegressionCandidate]:
        rows = self._conn.execute("SELECT payload FROM regression_cases").fetchall()
        return [RegressionCandidate.model_validate_json(r["payload"]) for r in rows]

    def get_exploit(self, exploit_id: str) -> ConfirmedExploit | None:
        r = self._conn.execute("SELECT payload FROM exploits WHERE exploit_id=?",
                               (exploit_id,)).fetchone()
        return ConfirmedExploit.model_validate_json(r["payload"]) if r else None

    # ── crash-resume support ───────────────────────────────────────────────
    def get_run(self, run_id: str) -> dict[str, Any] | None:
        r = self._conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(r) if r else None

    def latest_incomplete_run(self) -> str | None:
        """The most recent run whose `ended_at` is NULL — i.e. a run that crashed or was
        killed before it finished. end_run() (normal completion AND every halt path)
        stamps ended_at, so an unstamped run is exactly an interrupted one."""
        r = self._conn.execute(
            "SELECT run_id FROM runs WHERE ended_at IS NULL ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return r["run_id"] if r else None

    def get_run_plan(self, run_id: str) -> list[str] | None:
        """The ordered seed-id plan persisted at campaign start (an orchestrator/plan
        event), so a resume continues EXACTLY the originally-selected seeds — honoring
        the original categories/sweep/limit filters, not a fresh full sweep."""
        r = self._conn.execute(
            "SELECT detail FROM events WHERE run_id=? AND agent='orchestrator' AND action='plan' "
            "ORDER BY event_id LIMIT 1", (run_id,)).fetchone()
        if not r or not r["detail"]:
            return None
        try:
            return json.loads(r["detail"])
        except (ValueError, TypeError):
            return None

    def completed_seeds(self, run_id: str) -> set[str]:
        """Seed ids that completed for this run — a seed is DONE only when its base
        (generation-0) attempt has a recorded verdict, so a seed interrupted mid-flight
        (attempt written, verdict not) is re-run on resume rather than silently dropped."""
        rows = self._conn.execute(
            "SELECT DISTINCT a.seed_id FROM verdicts v JOIN attempts a ON a.attempt_id=v.attempt_id "
            "WHERE v.run_id=? AND a.generation=0 AND a.seed_id IS NOT NULL", (run_id,)
        ).fetchall()
        return {r["seed_id"] for r in rows}

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _dedupe_key(exploit: ConfirmedExploit) -> str:
        # Key on the ATTACKER-authored sequence + the invariant only. Target turns
        # (answers, latency-bearing burst results, LLM prose) vary run-to-run, so
        # including them would defeat "no duplicate for the same attack sequence".
        # Serialize with json (not a "|" join) so a message containing the delimiter
        # can never make two distinct sequences collide.
        payload = {
            "category": _enum(exploit.category),
            "invariant": exploit.target_invariant or "",
            "attacker": [t.content for t in exploit.minimal_transcript if t.role == "attacker"],
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def close(self) -> None:
        self._conn.close()


def _enum(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)
