"""Proves the suite-wide network guard (see `conftest._block_real_network`).

The guard exists because a swallowed respx miss once let a test make a real live
`/health` call and stay green. It must (a) trip loudly on a genuinely-unmocked
outbound call, and (b) stay completely out of the way of respx-mocked traffic —
respx intercepts at the httpx transport layer, *before* DNS, so a mocked request
never reaches `socket.getaddrinfo` and never sees the guard.
"""
from __future__ import annotations

import httpx
import pytest
import respx
from httpx import Response

BLOCKED_URL = "http://blocked.invalid/health"


async def test_unmocked_outbound_call_trips_the_guard():
    # No respx mock -> the request actually resolves DNS -> the guard fires.
    with pytest.raises(RuntimeError, match="Blocked real network access"):
        async with httpx.AsyncClient() as client:
            await client.get(BLOCKED_URL)


async def test_respx_mocked_call_bypasses_dns_and_the_guard():
    # respx intercepts at the transport layer before DNS, so getaddrinfo — and
    # therefore the guard — is never reached; the mocked response comes straight back.
    with respx.mock(assert_all_called=False) as router:
        router.get(BLOCKED_URL).mock(return_value=Response(200, json={"version": "t"}))
        async with httpx.AsyncClient() as client:
            resp = await client.get(BLOCKED_URL)
    assert resp.status_code == 200
    assert resp.json() == {"version": "t"}
