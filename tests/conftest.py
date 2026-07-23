"""Test hygiene: keep the suite hermetic.

A real `.env` (with a live ANTHROPIC_API_KEY and/or session cookie) must NEVER leak
into tests — that would spend real money, hit the live target, and make tests
flaky/non-deterministic. This autouse fixture forces both secrets empty for every
test and resets the cached Settings, regardless of what `.env` contains. Tests that
want an LLM/session path must construct `Settings(...)` with explicit values.
"""
from __future__ import annotations

import socket

import pytest

from adversaryforge.config import get_settings

# Hosts a test may legitimately resolve (never a real off-box target).
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@pytest.fixture(autouse=True)
def _hermetic_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    """Make any *real* outbound network call fail loudly instead of silently.

    A hermetic test must never touch the live target: the suite is meant to be
    fully offline (respx-mocked target, keyless settings). But respx failures can
    be swallowed by the client, so a genuinely-unmocked call could hit the network
    and still leave the test green (that is exactly how a real `/health` call once
    slipped through unnoticed).

    We guard at DNS resolution: `socket.getaddrinfo` is monkeypatched to raise for
    any host outside the localhost allow-list. respx intercepts at the httpx
    transport layer — *before* DNS — so respx-mocked requests never call
    `getaddrinfo` and are unaffected; only a truly-unmocked outbound call resolves
    and trips this guard. asyncio's event-loop resolver dispatches to this same
    `socket.getaddrinfo` (looked up at call time), so `httpx.AsyncClient` is
    covered by this one patch as well.
    """
    real_getaddrinfo = socket.getaddrinfo

    def _guarded_getaddrinfo(host, *args, **kwargs):
        if host not in _ALLOWED_HOSTS:
            raise RuntimeError(
                f"Blocked real network access to {host!r} in a test. Non-hermetic "
                "tests must be respx-mocked (respx intercepts before DNS) or point "
                "at localhost; a live call is never allowed to keep a test green."
            )
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield
