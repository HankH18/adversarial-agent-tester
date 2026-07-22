"""OpenRouter client for the Red Team attacker (Hermes 4).

OpenRouter exposes an OpenAI-compatible Chat Completions API, so this is a thin
httpx wrapper (no new dependency). Its `complete()` matches `LLMClient.complete`
exactly — (text, input_tokens, output_tokens, usd) — so the Mutator can use either
backend interchangeably.

Why it exists: routing the attacker to a Meta-Llama-based Hermes model via
OpenRouter, while the Judge stays on Claude, restores the *different model family*
structural independence the architecture calls for (see AS_BUILT §3 / residual R2).

Cost: OpenRouter returns the actual USD spend in `usage.cost` when we ask for it
(`usage.include=true`), so we meter real spend rather than estimate. A static
fallback in `pricing.py` covers the rare case it is absent.
"""
from __future__ import annotations

import httpx

from adversaryforge.config import Settings
from adversaryforge.llm.pricing import cost as _static_cost


class OpenRouterClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._key = settings.openrouter_api_key
        self._base = settings.openrouter_base_url.rstrip("/")

    def complete(
        self,
        system: str,
        user: str,
        model: str,
        max_tokens: int = 1024,
    ) -> tuple[str, int, int, float]:
        """One completion. Returns (text, input_tokens, output_tokens, usd)."""
        if not self._key:
            raise RuntimeError("OPENROUTER_API_KEY is not set — cannot call OpenRouter.")
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "usage": {"include": True},  # ask OpenRouter to return real USD cost
        }
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            # Optional attribution headers (harmless, no PII).
            "HTTP-Referer": "https://agentforge.hankholcomb.com",
            "X-Title": "AdversaryForge",
        }
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(f"{self._base}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices") or [{}]
        text = ((choices[0].get("message") or {}).get("content")) or ""
        usage = data.get("usage") or {}
        in_tok = int(usage.get("prompt_tokens", 0) or 0)
        out_tok = int(usage.get("completion_tokens", 0) or 0)
        # OpenRouter reports actual cost when usage.include=true; else fall back.
        usd = usage.get("cost")
        if usd is None:
            usd = _static_cost(model, in_tok, out_tok)
        return text, in_tok, out_tok, float(usd)
