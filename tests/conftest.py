"""Test hygiene: keep the suite hermetic.

A real `.env` (with a live ANTHROPIC_API_KEY and/or session cookie) must NEVER leak
into tests — that would spend real money, hit the live target, and make tests
flaky/non-deterministic. This autouse fixture forces both secrets empty for every
test and resets the cached Settings, regardless of what `.env` contains. Tests that
want an LLM/session path must construct `Settings(...)` with explicit values.
"""
from __future__ import annotations

import pytest

from adversaryforge.config import get_settings


@pytest.fixture(autouse=True)
def _hermetic_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("AGENTFORGE_SESSION_COOKIE", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
