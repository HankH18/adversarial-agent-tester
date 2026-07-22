"""Per-model USD pricing and a cost meter.

Rates are USD **per 1,000,000 tokens**, taken from the Anthropic pricing table
cached in the `claude-api` skill (cached 2026-06-24). Standard (non-introductory)
rates are used so the cost governor never *under*-estimates spend — an adversarial
suite that halts on a real budget is safer than one that runs past it.

This is the only place model prices live; `client.py` and the LLM agents meter
their spend through `cost()`.
"""
from __future__ import annotations

# model id -> (input_usd_per_million, output_usd_per_million)
_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    # Sonnet 5 standard rate; an introductory $2/$10 applies through 2026-08-31.
    # We meter at the standard rate so the governor errs on the safe (higher) side.
    "claude-sonnet-5": (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-fable-5": (10.00, 50.00),
    # OpenRouter — Red Team attacker (Hermes 4, Meta-Llama base). Static fallback
    # only: OpenRouter returns the true usd in usage.cost, which we prefer.
    "nousresearch/hermes-4-405b": (0.90, 0.90),
    "nousresearch/hermes-4-70b": (0.13, 0.13),
}

# Conservative default for an unknown model id: Opus-tier (the most expensive
# non-Fable option) so we never silently under-count.
_DEFAULT: tuple[float, float] = (5.00, 25.00)

_PER_MILLION = 1_000_000.0


def price_for(model: str) -> tuple[float, float]:
    """Return (input, output) USD-per-million for `model`, defaulting Opus-tier."""
    return _PRICES.get(model, _DEFAULT)


def cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """USD cost of a single completion for `model` at the given token counts."""
    in_rate, out_rate = price_for(model)
    return (int(input_tokens) * in_rate + int(output_tokens) * out_rate) / _PER_MILLION


__all__ = ["cost", "price_for"]
