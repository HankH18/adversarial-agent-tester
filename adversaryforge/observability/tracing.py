"""Fine-grained execution tracing — spans *inside* each agent.

A `trace(name, agent, **attrs)` context manager records a span: start/end wall
time, duration, parent (auto-linked via a contextvar stack so nested calls form a
tree), status, and arbitrary attributes you can add during the block via the
yielded `Span`. Spans persist to the observability store's `spans` table and render
as a tree with `adversaryforge trace <run_id>`.

Design:
  * **Non-invasive.** Deep code (a single Judge invariant rule, one LLM call) calls
    `trace(...)` without threading a tracer through signatures — the active tracer
    lives in a ContextVar, set for the duration of a run via `use_tracer(...)`.
  * **Zero-cost when off.** If no tracer is bound (unit tests, `trace_enabled=False`),
    `trace(...)` is a no-op that still yields a usable (discarded) Span.
  * **Async-safe.** ContextVars propagate across `await` within a task, so spans
    opened in async agent code (the executor) nest correctly.
"""
from __future__ import annotations

import contextvars
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

_current_tracer: contextvars.ContextVar["Tracer | None"] = contextvars.ContextVar(
    "adversaryforge_tracer", default=None
)
_current_span: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "adversaryforge_span", default=None
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Span:
    """A live span handle. Add attributes during the traced block."""

    __slots__ = ("span_id", "attrs", "status")

    def __init__(self, span_id: str) -> None:
        self.span_id = span_id
        self.attrs: dict[str, Any] = {}
        self.status = "ok"

    def set(self, key: str, value: Any) -> "Span":
        self.attrs[key] = value
        return self

    def update(self, **kv: Any) -> "Span":
        self.attrs.update(kv)
        return self

    def error(self, message: str) -> "Span":
        self.status = "error"
        self.attrs["error"] = message
        return self


class Tracer:
    """Bound to a store + run. Emits spans in monotonic `seq` order."""

    def __init__(self, store, run_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def emit(self, span: Span, parent_id: str | None, agent: str, name: str,
             start_ts: str, duration_ms: float) -> None:
        try:
            self._store.record_span({
                "span_id": span.span_id,
                "run_id": self._run_id,
                "parent_span_id": parent_id,
                "seq": self._next_seq(),
                "agent": agent,
                "name": name,
                "status": span.status,
                "start_ts": start_ts,
                "end_ts": _now_iso(),
                "duration_ms": round(duration_ms, 3),
                "attrs": span.attrs,
            })
        except Exception:
            # Tracing must never break a run.
            pass


def bind_tracer(tracer: "Tracer | None"):
    """Bind `tracer` as active; returns a token to pass to `unbind_tracer`."""
    return _current_tracer.set(tracer)


def unbind_tracer(token) -> None:
    _current_tracer.reset(token)


@contextmanager
def use_tracer(tracer: "Tracer | None") -> Iterator["Tracer | None"]:
    """Bind `tracer` as the active tracer for the duration of the block."""
    token = bind_tracer(tracer)
    try:
        yield tracer
    finally:
        unbind_tracer(token)


@contextmanager
def trace(name: str, agent: str, **attrs: Any) -> Iterator[Span]:
    """Record a span for the wrapped block. No-op (but still yields a Span) when no
    tracer is bound, so instrumentation is always safe to leave in place."""
    span = Span("sp_" + uuid.uuid4().hex[:12])
    if attrs:
        span.attrs.update(attrs)
    tracer = _current_tracer.get()
    if tracer is None:
        yield span
        return
    parent = _current_span.get()
    start_ts = _now_iso()
    started = time.perf_counter()
    span_token = _current_span.set(span.span_id)
    try:
        yield span
    except Exception as exc:  # record the failure, then re-raise
        span.error(f"{type(exc).__name__}: {exc}")
        raise
    finally:
        duration_ms = (time.perf_counter() - started) * 1000
        _current_span.reset(span_token)
        tracer.emit(span, parent, agent, name, start_ts, duration_ms)


def render_tree(spans: list[dict[str, Any]]) -> list[str]:
    """Render spans as an indented tree (chronological within each parent)."""
    children: dict[str | None, list[dict]] = {}
    for s in spans:
        children.setdefault(s.get("parent_span_id"), []).append(s)
    for kids in children.values():
        kids.sort(key=lambda s: s.get("seq") or 0)

    lines: list[str] = []

    def walk(parent_id: str | None, depth: int) -> None:
        for s in children.get(parent_id, []):
            indent = "  " * depth
            dur = s.get("duration_ms")
            dur_s = f"{dur:.1f}ms" if dur is not None else "—"
            mark = "✗" if s.get("status") == "error" else "•"
            attrs = s.get("attrs") or {}
            key_attrs = _summarize_attrs(attrs)
            lines.append(f"{indent}{mark} [{s['agent']}] {s['name']}  ({dur_s}){key_attrs}")
            walk(s["span_id"], depth + 1)

    walk(None, 0)
    return lines


def _summarize_attrs(attrs: dict[str, Any]) -> str:
    if not attrs:
        return ""
    parts = []
    for k, v in attrs.items():
        sv = str(v)
        if len(sv) > 60:
            sv = sv[:57] + "…"
        parts.append(f"{k}={sv}")
    return "  " + " ".join(parts)
