"""Seed model + library loader.

A seed is a *declarative, reproducible* attack case. It is deliberately not a raw
payload string: it names the invariant it tries to falsify, the OWASP categories it
maps to, the safe behavior expected, and whether it belongs in the regression
suite. Every seed also declares its **test-design role** — boundary / invariant /
regression — per the engineering requirement that static payload lists are not
sufficient.

Seeds live in `evals/seeds/*.yaml`. Multi-turn attacks are a list of `steps`; each
step is one request whose response becomes a target turn in the transcript.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from adversaryforge.contracts import AttackCategory, OwaspLlm, OwaspWeb

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SEEDS_DIR = _REPO_ROOT / "evals" / "seeds"


class Step(BaseModel):
    """One request in an attack sequence."""

    model_config = ConfigDict(extra="forbid")
    kind: Literal["http", "chat", "burst"] = "chat"
    burst_count: int = Field(default=12, le=20, description="For kind=burst: bounded rapid requests.")
    # generic http
    method: str = "POST"
    path: str = "/v1/chat"
    json_body: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    params: dict[str, Any] | None = None
    # chat convenience (compiled into json_body if kind == chat)
    message: str | None = None
    patient_id: int = 1
    clinician_id: int | None = None
    conversation_id_from_step: int | None = Field(
        default=None,
        description="0-based index of an earlier step whose response conversation_id "
        "to thread into this turn (multi-turn state).",
    )
    document_ids: list[str] | None = None

    @model_validator(mode="after")
    def _burst_only_hits_cheap_liveness_endpoints(self) -> "Step":
        # Structural guarantee (fails at seed-load, not mid-campaign): a burst may
        # only target the cheap liveness endpoints, so a seed-author mistake can
        # never turn the rate-limit probe into a real DoS of an expensive route.
        if self.kind == "burst" and self.path not in ("/health", "/ready"):
            raise ValueError(
                f"burst steps may only target /health or /ready, not {self.path!r}"
            )
        return self

    upload_file: dict[str, str] | None = Field(
        default=None,
        description="For a multipart upload step: {filename, content_type, text}. The executor "
        "sends it as multipart 'file' (+ patient_id/clinician_id form fields from json_body) and "
        "captures the returned document id. Later steps use the sentinel 'from-upload' in "
        "document_ids to reference it.",
    )
    note: str = ""


class Seed(BaseModel):
    """A reproducible adversarial test case."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: AttackCategory
    subcategory: str = ""
    title: str
    description: str = ""
    target_invariant: str
    expected_safe: str = Field(description="The safe behavior; may encode 'latency_ms<=N'.")
    test_role: Literal["boundary", "invariant", "regression"] = "invariant"
    steps: list[Step] = Field(min_length=1)
    owasp_web: list[OwaspWeb] = Field(default_factory=list)
    owasp_llm: list[OwaspLlm] = Field(default_factory=list)
    @property
    def is_write_probe(self) -> bool:
        """True if any step issues a write verb to the target's /v1/writes* routes.
        Such seeds are excluded from campaigns unless the operator opts in."""
        for st in self.steps:
            if st.kind != "http":
                continue
            p = (st.path or "").split("?", 1)[0]
            if (st.method or "").upper() in {"POST", "PUT", "PATCH", "DELETE"} and (
                p == "/v1/writes" or p.startswith("/v1/writes/")
            ):
                return True
        return False

    add_to_regression: bool = True
    requires_auth: bool = Field(
        default=True,
        description="If True, the step hits an authenticated route; skipped when no "
        "session is configured (but staged to auto-run once a cookie lands).",
    )
    severity_hint: str = "medium"


class SeedLibrary(BaseModel):
    seeds: list[Seed]

    @staticmethod
    def load(directory: Path | str = SEEDS_DIR) -> "SeedLibrary":
        directory = Path(directory)
        seeds: list[Seed] = []
        seen: set[str] = set()
        for path in sorted(directory.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text()) or []
            for raw in data:
                seed = Seed.model_validate(raw)
                if seed.id in seen:
                    raise ValueError(f"Duplicate seed id: {seed.id} in {path}")
                seen.add(seed.id)
                seeds.append(seed)
        return SeedLibrary(seeds=seeds)

    def by_category(self) -> dict[str, list[Seed]]:
        out: dict[str, list[Seed]] = {}
        for s in self.seeds:
            out.setdefault(_enum(s.category), []).append(s)
        return out

    def categories(self) -> set[str]:
        return {_enum(s.category) for s in self.seeds}

    def runnable(self, *, authenticated: bool, allow_write_probe: bool | None = None) -> list[Seed]:
        """Seeds we can execute now. Unauthenticated seeds always; authenticated
        seeds only when a session is configured; **write-probe seeds only when the
        operator opts in** (default off) so the platform stays read-only against the
        target. `allow_write_probe=None` reads the setting."""
        if allow_write_probe is None:
            from adversaryforge.config import get_settings

            allow_write_probe = get_settings().allow_write_probe
        return [
            s for s in self.seeds
            if (authenticated or not s.requires_auth)
            and (allow_write_probe or not s.is_write_probe)
        ]


def _enum(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)
