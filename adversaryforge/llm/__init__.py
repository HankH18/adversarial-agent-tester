"""The platform's own LLM layer — the single place that talks to the Anthropic API.

Everything here is key-optional and import-safe: no client is constructed at
import time, and every agent degrades to deterministic/offline behavior when
`settings.has_llm` is False.

  * `pricing`  — per-model USD cost table + `cost()`.
  * `LLMClient` — lazy, metered Anthropic Messages wrapper (raises only when called
    without a key).
  * `make_llm_adjudicator` — the Judge's optional LLM second opinion (info-barriered
    to a JudgeView; returns None without a key).
  * `Mutator` — turns a partial success into N distinct variants (LLM or a
    deterministic transform bank).
"""
from __future__ import annotations

from . import pricing
from .client import LLMClient
from .judge_llm import make_llm_adjudicator
from .mutator import Mutator

__all__ = ["pricing", "LLMClient", "make_llm_adjudicator", "Mutator"]
