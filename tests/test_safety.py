"""Blast-radius / platform-safety controls: the client-side write guard, write-probe
seed exclusion, and the burst-endpoint restriction. These make the 'read-only by
default' guarantee self-enforced rather than a doc promise."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from adversaryforge.config import Settings
from adversaryforge.redteam.seeds import Seed, SeedLibrary, Step
from adversaryforge.target.adapter import agentforge_adapter
from adversaryforge.target.client import TargetClient
from adversaryforge.target.session import AnonymousSession

BASE = "http://test.local"


def _s(**kw):
    return Settings(target_base_url=BASE, min_request_gap_s=0.0, max_concurrency=4, **kw)


async def test_write_guard_blocks_writes_by_default_and_never_sends():
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE}/v1/writes").mock(return_value=Response(200, json={}))
        async with TargetClient(agentforge_adapter(BASE), AnonymousSession(), _s()) as c:
            resp = await c.request("POST", "/v1/writes", json={"patient_id": 1, "value": "x"})
    assert resp.status_code == 0
    assert resp.error == "blocked_by_write_guard"
    assert not route.called  # the write was NEVER dispatched to the target


async def test_write_guard_allows_probe_with_opt_in():
    with respx.mock(assert_all_called=True) as router:
        router.post(f"{BASE}/v1/writes").mock(return_value=Response(503, json={}))
        async with TargetClient(agentforge_adapter(BASE), AnonymousSession(),
                                _s(allow_write_probe=True)) as c:
            resp = await c.request("POST", "/v1/writes", json={"patient_id": 1})
    assert resp.status_code == 503  # opt-in -> probe reaches the target (expects rejection)


async def test_write_guard_does_not_block_reads():
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{BASE}/v1/writes/abc").mock(return_value=Response(404, json={}))
        async with TargetClient(agentforge_adapter(BASE), AnonymousSession(), _s()) as c:
            resp = await c.request("GET", "/v1/writes/abc")
    assert resp.status_code == 404  # GET is a read; the guard only blocks write verbs


def _write_seed():
    return Seed.model_validate({
        "id": "tm-write", "category": "tool_misuse", "title": "write probe",
        "target_invariant": "INV-WRITE-GATED", "expected_safe": "503/403", "requires_auth": True,
        "steps": [{"kind": "http", "method": "POST", "path": "/v1/writes",
                   "json_body": {"patient_id": 1}}]})


def _chat_seed():
    return Seed.model_validate({
        "id": "pi-x", "category": "prompt_injection", "title": "t",
        "target_invariant": "INV-INJECTION-INERT", "expected_safe": "inert", "requires_auth": True,
        "steps": [{"kind": "chat", "message": "hi", "patient_id": 1}]})


def test_write_probe_seeds_excluded_from_runnable_by_default():
    lib = SeedLibrary(seeds=[_write_seed(), _chat_seed()])
    assert _write_seed().is_write_probe is True
    assert _chat_seed().is_write_probe is False
    default_ids = {s.id for s in lib.runnable(authenticated=True, allow_write_probe=False)}
    assert "tm-write" not in default_ids  # excluded by default
    optin_ids = {s.id for s in lib.runnable(authenticated=True, allow_write_probe=True)}
    assert "tm-write" in optin_ids  # included only on explicit opt-in


def test_burst_step_rejects_expensive_endpoints_at_load():
    Step.model_validate({"kind": "burst", "path": "/health", "burst_count": 10})  # ok
    Step.model_validate({"kind": "burst", "path": "/ready", "burst_count": 10})   # ok
    with pytest.raises(Exception):  # a real endpoint would make the burst a genuine DoS
        Step.model_validate({"kind": "burst", "path": "/v1/chat", "burst_count": 10})
