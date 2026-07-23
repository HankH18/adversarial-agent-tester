"""TargetClient — the single throttled, auditable HTTP path to the target.

Two responsibilities beyond plain HTTP:
  1. **Self-throttle.** The target has NO inbound rate limiting (recon:
     `api/app.py:99-212`). The platform must not become the thing that DoSes a
     system physicians depend on: a concurrency cap + a minimum gap between
     requests, both operator-tunable, gate every call.
  2. **Full capture.** Every request/response is captured verbatim (status,
     headers, body, latency) so the Judge can adjudicate and the observability
     store can replay it. The attacker never sees target-side cost — it isn't on
     the wire — so latency/bytes are the only target-cost signals we record.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from adversaryforge.config import Settings
from adversaryforge.target.adapter import TargetAdapter, normalized_path
from adversaryforge.target.session import SessionProvider


def _resolve_allowed_hosts(settings: Settings, adapter: TargetAdapter) -> set[str]:
    """The set of hostnames this client is permitted to dispatch to. Defaults to the
    configured target host plus loopback (the local-target workflow), and is widened
    only by explicit operator opt-in via ADVERSARYFORGE_TARGET_ALLOWLIST. This is the
    ethics boundary made mechanical: 'only test systems you're authorized to' becomes
    a client-enforced refusal, not a promise."""
    hosts = {"localhost", "127.0.0.1"}
    base_host = (urlsplit(adapter.base_url).hostname or "").lower()
    if base_host:
        hosts.add(base_host)
    extra = getattr(settings, "target_allowlist", "") or ""
    for h in extra.replace(",", " ").split():
        h = h.strip().lower()
        if h:
            hosts.add(h)
    return hosts


@dataclass
class TargetResponse:
    """A captured, replayable interaction with the target."""

    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Any
    status_code: int
    response_headers: dict[str, str]
    body_text: str
    latency_ms: float
    correlation_id: str
    error: str | None = None

    @property
    def json(self) -> Any | None:
        import json as _json

        try:
            return _json.loads(self.body_text)
        except Exception:
            return None

    def to_record(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "body_text": self.body_text[:20000],
            "latency_ms": round(self.latency_ms, 1),
            "correlation_id": self.correlation_id,
            "error": self.error,
        }


class TargetClient:
    """Async, throttled, auditable client. One per campaign."""

    def __init__(
        self,
        adapter: TargetAdapter,
        session: SessionProvider,
        settings: Settings,
    ) -> None:
        self._adapter = adapter
        self._session = session
        self._settings = settings
        # Blast-radius allowlist, resolved once at construction. Fail FAST on a
        # host-less base_url — a misconfigured target must not silently dispatch nowhere
        # (or, worse, let a relative join land somewhere unintended).
        if not (urlsplit(adapter.base_url).hostname or ""):
            raise ValueError(
                f"target_base_url has no host, refusing to build a client: {adapter.base_url!r}"
            )
        self._allowed_hosts = _resolve_allowed_hosts(settings, adapter)
        self._sem = asyncio.Semaphore(max(1, settings.max_concurrency))
        self._min_gap = max(0.0, settings.min_request_gap_s)
        self._last_request_at = 0.0
        self._gap_lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout_s,
            follow_redirects=False,  # redirects are attack signal (open-redirect, OAuth flow)
        )

    async def __aenter__(self) -> "TargetClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    _WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def _is_blocked_write(self, method: str, path: str) -> bool:
        if getattr(self._settings, "allow_write_probe", False):
            return False
        if method.upper() not in self._WRITE_METHODS:
            return False
        # Canonicalize to the path component. normalized_path also collapses a leading
        # '//' — which urlsplit would otherwise mis-parse as authority, letting
        # //v1/writes (or https://host//v1/writes) slip past this prefix match.
        p = normalized_path(path)
        return p == "/v1/writes" or p.startswith("/v1/writes/")

    def _host_allowed(self, url: str) -> bool:
        """True iff the resolved request host is on the allowlist. Compared by hostname
        (port-insensitive, so localhost:8080 works) — an absolute-URL step to any other
        host is refused BEFORE dispatch, so the platform can never touch a system the
        operator has not authorized. A URL whose authority won't even parse fails CLOSED
        (returns False → blocked), never an uncaught exception out of `request()`."""
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            return False
        return host in self._allowed_hosts

    def _same_host(self, url: str) -> bool:
        """True if `url` targets the configured target host. Relative paths (dispatched
        as base_url + path) are always same-host; an absolute URL to any other host is
        not — so session credentials are never sent off-target."""
        return urlsplit(url).netloc == urlsplit(self._adapter.base_url).netloc

    async def _pace(self) -> None:
        """Enforce the minimum inter-request gap (in addition to the sem cap)."""
        async with self._gap_lock:
            now = time.monotonic()
            wait = self._min_gap - (now - self._last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        files: Any | None = None,
        data: dict[str, Any] | None = None,
    ) -> TargetResponse:
        corr = uuid.uuid4().hex
        url = self._adapter.base_url + path if path.startswith("/") else path

        # Blast-radius guard #0 (outermost): refuse any request whose resolved host is
        # not on the allowlist. An absolute-URL / mutated step naming a foreign host is
        # NEVER dispatched — the platform only ever touches authorized targets, and a
        # physician session categorically cannot leak off-host because the request never
        # leaves the process.
        if not self._host_allowed(url):
            return TargetResponse(
                method=method, url=url, request_headers={"X-Correlation-Id": corr},
                request_body=json if json is not None else params, status_code=0,
                response_headers={}, body_text="client-side host-allowlist guard: request "
                f"NOT sent — off-target or unparseable host in {url!r} (allowed: "
                f"{sorted(self._allowed_hosts)}; widen via ADVERSARYFORGE_TARGET_ALLOWLIST)",
                latency_ms=0.0, correlation_id=corr, error="blocked_by_host_allowlist")

        # Blast-radius guard: default-deny any write to /v1/writes*. The platform is
        # read-only against the target unless the operator explicitly opts in
        # (allow_write_probe). This is a self-enforced control at the HTTP layer, not
        # a promise outsourced to the target's own feature flag.
        if self._is_blocked_write(method, path):
            return TargetResponse(
                method=method, url=url, request_headers={"X-Correlation-Id": corr},
                request_body=json if json is not None else params, status_code=0,
                response_headers={}, body_text="client-side default-deny write guard: "
                "request NOT sent (set ADVERSARYFORGE_ALLOW_WRITE_PROBE=1 to probe the "
                "target's write-gate)", latency_ms=0.0, correlation_id=corr,
                error="blocked_by_write_guard")

        req_headers: dict[str, str] = {"X-Correlation-Id": corr}
        # Attach session credentials (cookie / auth) ONLY when the request targets the
        # configured host. An absolute-URL step to a foreign host must never carry the
        # physician session off-target — same blast-radius discipline as the write guard.
        if self._same_host(url):
            req_headers.update(self._session.headers())
        if headers:
            req_headers.update(headers)

        async with self._sem:
            await self._pace()
            started = time.perf_counter()
            try:
                resp = await self._client.request(
                    method,
                    url,
                    json=json if files is None else None,
                    headers=req_headers,
                    params=params,
                    files=files,
                    data=data,
                )
                latency = (time.perf_counter() - started) * 1000
                return TargetResponse(
                    method=method,
                    url=url,
                    request_headers=req_headers,
                    request_body=json if json is not None else params,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    body_text=resp.text,
                    latency_ms=latency,
                    correlation_id=corr,
                )
            except Exception as exc:  # network error, timeout, etc.
                latency = (time.perf_counter() - started) * 1000
                return TargetResponse(
                    method=method,
                    url=url,
                    request_headers=req_headers,
                    request_body=json if json is not None else params,
                    status_code=0,
                    response_headers={},
                    body_text="",
                    latency_ms=latency,
                    correlation_id=corr,
                    error=f"{type(exc).__name__}: {exc}",
                )

    # --- Convenience for the primary chat surface --------------------------
    async def chat(
        self,
        message: str,
        patient_id: int = 1,
        *,
        conversation_id: int | None = None,
        clinician_id: int | None = None,
        document_ids: list[str] | None = None,
    ) -> TargetResponse:
        body: dict[str, Any] = {"message": message, "patient_id": patient_id}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        if clinician_id is not None:
            body["clinician_id"] = clinician_id
        if document_ids:
            body["document_ids"] = document_ids
        return await self.request("POST", "/v1/chat", json=body)
