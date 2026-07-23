"""Fine-grained execution tracing — spans nest into a tree, persist, and render."""
from __future__ import annotations

from adversaryforge.observability.store import Store
from adversaryforge.observability.tracing import Tracer, render_tree, trace, use_tracer


def test_trace_is_a_noop_without_a_bound_tracer():
    # Instrumentation must be safe to leave in place with no tracer (unit tests).
    with trace("x", "judge") as sp:
        sp.set("k", 1)  # no exception, nothing recorded, no crash


def test_nested_spans_form_a_tree(tmp_path):
    store = Store(tmp_path / "t.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    with use_tracer(Tracer(store, rid)):
        with trace("orchestrator.run_seed", "orchestrator", seed="s1") as p:
            p.set("outcome", "partial")
            with trace("judge.evaluate", "judge", invariant="INV-X"):
                with trace("judge.rule", "judge", invariant="INV-X") as r:
                    r.set("fired", True)

    spans = {s["name"]: s for s in store.get_spans(rid)}
    assert set(spans) == {"orchestrator.run_seed", "judge.evaluate", "judge.rule"}
    assert spans["judge.evaluate"]["parent_span_id"] == spans["orchestrator.run_seed"]["span_id"]
    assert spans["judge.rule"]["parent_span_id"] == spans["judge.evaluate"]["span_id"]
    assert spans["judge.rule"]["attrs"]["fired"] is True
    assert spans["orchestrator.run_seed"]["duration_ms"] is not None


def test_render_tree_indents_by_depth(tmp_path):
    store = Store(tmp_path / "t.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    with use_tracer(Tracer(store, rid)):
        with trace("parent", "orchestrator"):
            with trace("child", "judge"):
                pass
    lines = render_tree(store.get_spans(rid))
    parent_line = next(x for x in lines if "parent" in x)
    child_line = next(x for x in lines if "child" in x)
    assert not parent_line.startswith("  ")
    assert child_line.startswith("  ")  # deeper = indented


def test_span_captures_error_status(tmp_path):
    store = Store(tmp_path / "t.sqlite")
    rid = store.start_run("http://t", "v", "test", False)
    with use_tracer(Tracer(store, rid)):
        try:
            with trace("boom", "redteam"):
                raise ValueError("nope")
        except ValueError:
            pass
    span = store.get_spans(rid)[0]
    assert span["status"] == "error"
    assert "nope" in span["attrs"]["error"]
