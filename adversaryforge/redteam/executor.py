"""SeedExecutor — turns a declarative Seed into an executed AttackAttempt.

It compiles each step into an HTTP request, drives the target through the throttled
client, and assembles the transcript the Judge will read. Conversation state
(multi-turn) is threaded by carrying a prior step's `conversation_id` forward.

The executor is intentionally dumb about success — it never decides whether an
attack worked. That is the Judge's job. This keeps generation and evaluation in
separate contexts (the core independence requirement).
"""
from __future__ import annotations

import uuid
from typing import Any

from adversaryforge.contracts import AttackAttempt, TranscriptTurn
from adversaryforge.redteam.seeds import Seed, Step
from adversaryforge.target.client import TargetClient, TargetResponse


class SeedExecutor:
    def __init__(self, client: TargetClient) -> None:
        self._client = client

    async def run(self, seed: Seed, directive_id: str, *, generation: int = 0,
                  parent_attempt_id: str | None = None,
                  override_messages: list[str] | None = None) -> AttackAttempt:
        transcript: list[TranscriptTurn] = []
        step_convos: list[int | None] = []

        for i, step in enumerate(seed.steps):
            msg_override = None
            if override_messages is not None and i < len(override_messages):
                msg_override = override_messages[i]

            if step.kind == "burst":
                transcript.append(TranscriptTurn(
                    role="attacker",
                    content=f"[burst x{step.burst_count}] {step.method} {step.path}"))
                transcript.append(await self._burst(step))
                step_convos.append(None)
                continue

            method, path, body, headers, params = self._compile(step, step_convos, msg_override)
            attacker_content = self._attacker_summary(step, body, msg_override)
            transcript.append(TranscriptTurn(role="attacker", content=attacker_content))

            resp = await self._client.request(
                method, path, json=body, headers=headers, params=params
            )
            transcript.append(self._target_turn(resp))
            step_convos.append(self._extract_conversation_id(resp))

        return AttackAttempt(
            attempt_id="at_" + uuid.uuid4().hex[:12],
            directive_id=directive_id,
            seed_id=seed.id,
            category=seed.category,
            subcategory=seed.subcategory,
            generation=generation,
            parent_attempt_id=parent_attempt_id,
            target_invariant=seed.target_invariant,
            expected_safe=seed.expected_safe,
            transcript=transcript,
            owasp_web=seed.owasp_web,
            owasp_llm=seed.owasp_llm,
            # attacker-private fields (Judge never sees these):
            technique=seed.subcategory or seed.category.value if hasattr(seed.category, "value") else "",
            intent=seed.title,
        )

    async def _burst(self, step: Step) -> TranscriptTurn:
        """Fire a bounded, concurrent burst to probe for rate limiting. Restricted
        to cheap liveness endpoints so it can never be a real DoS itself."""
        import asyncio

        import httpx

        n = min(step.burst_count, 20)
        base = self._client._adapter.base_url  # noqa: SLF001
        url = base + step.path if step.path.startswith("/") else step.path
        started = __import__("time").perf_counter()
        async with httpx.AsyncClient(timeout=15.0) as c:
            results = await asyncio.gather(
                *[c.request(step.method, url) for _ in range(n)],
                return_exceptions=True,
            )
        elapsed_ms = (__import__("time").perf_counter() - started) * 1000
        statuses = [r.status_code if hasattr(r, "status_code") else 0 for r in results]
        return TranscriptTurn(
            role="target",
            content=f"burst statuses={statuses} in {elapsed_ms:.0f}ms",
            http_status=statuses[0] if statuses else 0,
            raw={"_burst_statuses": statuses, "_burst_elapsed_ms": elapsed_ms,
                 "_latency_ms": elapsed_ms},
        )

    # ── compilation ────────────────────────────────────────────────────────
    def _compile(self, step: Step, step_convos: list[int | None], msg_override: str | None):
        headers = dict(step.headers or {})
        params = dict(step.params or {})
        if step.kind == "chat":
            body: dict[str, Any] = {
                "message": msg_override if msg_override is not None else (step.message or ""),
                "patient_id": step.patient_id,
            }
            if step.clinician_id is not None:
                body["clinician_id"] = step.clinician_id
            if step.document_ids:
                body["document_ids"] = step.document_ids
            if step.conversation_id_from_step is not None:
                idx = step.conversation_id_from_step
                if 0 <= idx < len(step_convos) and step_convos[idx] is not None:
                    body["conversation_id"] = step_convos[idx]
            return "POST", "/v1/chat", body, headers, params
        # generic http
        body = dict(step.json_body) if step.json_body else None
        if body and msg_override is not None and "message" in body:
            body["message"] = msg_override
        return step.method, step.path, body, headers, params

    @staticmethod
    def _attacker_summary(step: Step, body: Any, msg_override: str | None) -> str:
        if step.kind == "chat" or (isinstance(body, dict) and "message" in body):
            msg = msg_override if msg_override is not None else (
                step.message or (body or {}).get("message", "")
            )
            return str(msg)
        return f"{step.method} {step.path} {body if body is not None else ''}".strip()

    @staticmethod
    def _target_turn(resp: TargetResponse) -> TranscriptTurn:
        j = resp.json
        raw: dict[str, Any] = {}
        if isinstance(j, dict):
            raw = dict(j)
        raw["_latency_ms"] = resp.latency_ms
        raw["_status"] = resp.status_code
        content = ""
        if isinstance(j, dict) and "answer" in j:
            content = str(j.get("answer") or "")
        else:
            content = resp.body_text[:4000]
        return TranscriptTurn(
            role="target",
            content=content,
            http_status=resp.status_code,
            raw=raw,
        )

    @staticmethod
    def _extract_conversation_id(resp: TargetResponse) -> int | None:
        j = resp.json
        if isinstance(j, dict) and isinstance(j.get("conversation_id"), int):
            return j["conversation_id"]
        return None
