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
    )

    # --- LLM (platform's own agents) ---------------------------------------
    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")
    judge_model: str = Field(default="claude-opus-4-8", validation_alias="ADVERSARYFORGE_JUDGE_MODEL")
    redteam_model: str = Field(
        default="claude-sonnet-5", validation_alias="ADVERSARYFORGE_REDTEAM_MODEL"
    )
    doc_model: str = Field(default="claude-sonnet-5", validation_alias="ADVERSARYFORGE_DOC_MODEL")

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

    # --- Storage -----------------------------------------------------------
    data_dir: Path = Field(default=_REPO_ROOT / "data", validation_alias="ADVERSARYFORGE_DATA_DIR")

    # --- Derived / convenience --------------------------------------------
    @property
    def has_llm(self) -> bool:
        return bool(self.anthropic_api_key.strip())

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
