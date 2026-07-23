"""Central configuration. Every secret and tunable is read here — nothing hardcoded.

Reads `.env` (git-ignored) via pydantic-settings. The two secrets that unlock full
live coverage (`ANTHROPIC_API_KEY`, `AGENTFORGE_SESSION_COOKIE`) are optional: the
platform runs and produces real evidence without them (deterministic Judge +
unauthenticated live surface + subagent-driven attacks). See `.env.example`.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,  # allow Settings(field_name=...) in tests, not just the env alias
    )

    # --- LLM (platform's own agents) ---------------------------------------
    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")
    judge_model: str = Field(default="claude-opus-4-8", validation_alias="ADVERSARYFORGE_JUDGE_MODEL")
    redteam_model: str = Field(
        default="claude-sonnet-5", validation_alias="ADVERSARYFORGE_REDTEAM_MODEL"
    )
    doc_model: str = Field(default="claude-sonnet-5", validation_alias="ADVERSARYFORGE_DOC_MODEL")

    # Red Team attacker via OpenRouter (Hermes 4). Present ⇒ the Red Team/mutator runs
    # on a DIFFERENT model family from the Claude Judge (restores structural independence).
    openrouter_api_key: str = Field(default="", validation_alias="OPENROUTER_API_KEY")
    openrouter_redteam_model: str = Field(
        default="nousresearch/hermes-4-405b",
        validation_alias="ADVERSARYFORGE_OPENROUTER_REDTEAM_MODEL",
    )
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1", validation_alias="ADVERSARYFORGE_OPENROUTER_BASE_URL"
    )

    # --- Target ------------------------------------------------------------
    target_base_url: str = Field(
        default="https://agentforge.hankholcomb.com",
        validation_alias="ADVERSARYFORGE_TARGET_BASE_URL",
    )
    session_cookie: str = Field(default="", validation_alias="AGENTFORGE_SESSION_COOKIE")

    # --- Self-throttle (target has NO inbound rate limiting; we must not DoS it) ---
    max_concurrency: int = Field(default=2, validation_alias="ADVERSARYFORGE_MAX_CONCURRENCY")
    min_request_gap_s: float = Field(
        default=0.5, validation_alias="ADVERSARYFORGE_MIN_REQUEST_GAP_S"
    )
    request_timeout_s: float = Field(
        default=30.0, validation_alias="ADVERSARYFORGE_REQUEST_TIMEOUT_S"
    )

    # --- Cost governor -----------------------------------------------------
    nosignal_halt_usd: float = Field(
        default=2.0, validation_alias="ADVERSARYFORGE_NOSIGNAL_HALT_USD"
    )

    # --- Judge drift gate --------------------------------------------------
    # Cohen's-kappa floor for the per-run Judge calibration against the frozen gold
    # set. Below this, the campaign FAILS CLOSED (a drifting Judge is not trusted).
    # Set to 0 to disable the gate.
    judge_kappa_threshold: float = Field(
        default=0.8, validation_alias="ADVERSARYFORGE_JUDGE_KAPPA_THRESHOLD"
    )
    # Multi-vote adjudication panel: N independent LLM votes on each ambiguous verdict,
    # aggregated by majority. 1 = single call (default). Higher N trades cost for
    # robustness against single-call variance on the LLM tier.
    judge_panel_votes: int = Field(
        default=1, validation_alias="ADVERSARYFORGE_JUDGE_PANEL_VOTES"
    )

    # --- Blast-radius control ----------------------------------------------
    # The platform is READ-ONLY against the target by default: write-path seeds
    # are excluded from campaigns AND a client-side default-deny guard refuses any
    # POST/PUT/PATCH/DELETE to /v1/writes*. Verifying the target's own write-gate
    # (INV-WRITE-GATED) requires this explicit operator opt-in, which sends a single
    # harmless probe expecting a 503/403 — no write is ever committed.
    allow_write_probe: bool = Field(
        default=False, validation_alias="ADVERSARYFORGE_ALLOW_WRITE_PROBE"
    )

    # --- Execution tracing -------------------------------------------------
    # Fine-grained per-agent span tracing to the observability store. Low
    # overhead; on by default. Set 0/false to disable.
    trace_enabled: bool = Field(default=True, validation_alias="ADVERSARYFORGE_TRACE")

    # --- Storage -----------------------------------------------------------
    data_dir: Path = Field(default=_REPO_ROOT / "data", validation_alias="ADVERSARYFORGE_DATA_DIR")

    # --- Derived / convenience --------------------------------------------
    @property
    def has_llm(self) -> bool:
        return bool(self.anthropic_api_key.strip())

    @property
    def has_openrouter(self) -> bool:
        return bool(self.openrouter_api_key.strip())

    @property
    def has_session(self) -> bool:
        return bool(self.session_cookie.strip())

    @property
    def db_path(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "adversaryforge.sqlite"

    @property
    def is_local_target(self) -> bool:
        return "localhost" in self.target_base_url or "127.0.0.1" in self.target_base_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
