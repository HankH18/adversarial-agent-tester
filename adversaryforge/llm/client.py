"""The platform's single Anthropic API entry point.

This is the ONLY module that constructs an `anthropic.Anthropic` client or calls
the Messages API. Everything here is key-optional and import-safe:

  * `anthropic` is imported lazily, inside `_ensure()`, so importing this module
    never requires the package to be installed.
  * The client is constructed on first use, from `settings.anthropic_api_key`.
  * With no key, `complete()` raises a clear `RuntimeError` *when called* — never
    at import, and never at construction. Callers guard on `settings.has_llm`.

Deterministic-first is a platform invariant: the Judge, Mutator, and Doc agents
all degrade to offline behavior when `has_llm` is False, so this client only ever
runs when a key is present.
"""
from __future__ import annotations

from .pricing import cost


class LLMClient:
    """Lazy, metered wrapper over the Anthropic Messages API."""

    def __init__(self, settings) -> None:
        # No client construction here — import-safe and key-optional.
        self._settings = settings
        self._client = None

    # ── lazy construction ──────────────────────────────────────────────────
    def _ensure(self):
        if self._client is not None:
            return self._client
        key = (getattr(self._settings, "anthropic_api_key", "") or "").strip()
        if not key:
            raise RuntimeError(
                "LLMClient.complete() called with no ANTHROPIC_API_KEY set. "
                "The platform degrades to deterministic/offline behavior without "
                "a key; guard on settings.has_llm before calling the LLM."
            )
        try:
            import anthropic  # imported lazily so this module is import-safe
        except ImportError as exc:  # pragma: no cover - env always has anthropic
            raise RuntimeError(
                "The 'anthropic' package is not installed; cannot reach the LLM."
            ) from exc
        self._client = anthropic.Anthropic(api_key=key)
        return self._client

    # ── public API ─────────────────────────────────────────────────────────
    def complete(
        self,
        system: str,
        user: str,
        model: str,
        max_tokens: int = 1024,
    ) -> tuple[str, int, int, float]:
        """Run one completion. Returns (text, input_tokens, output_tokens, usd)."""
        client = self._ensure()
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            block.text
            for block in resp.content
            if getattr(block, "type", None) == "text"
        )
        in_tok = int(getattr(resp.usage, "input_tokens", 0) or 0)
        out_tok = int(getattr(resp.usage, "output_tokens", 0) or 0)
        usd = cost(model, in_tok, out_tok)
        return text, in_tok, out_tok, usd


__all__ = ["LLMClient"]
