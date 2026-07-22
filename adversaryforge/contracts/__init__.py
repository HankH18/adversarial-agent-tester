"""Versioned, typed inter-agent contracts.

Every message that crosses an agent boundary is one of these models. Both the
producer and the consumer validate against it; the canonical JSON Schemas live in
the top-level `/contracts` directory and are generated from these models
(`scripts/export_contracts.py`), so the two can never silently drift. Breaking a
shape requires a version bump + a migration note (see `/contracts/CHANGELOG.md`).

Trust-boundary note: `AttackAttempt` carries the Red Team's `technique` and
`intent`, but the Judge is constructed to read only `.transcript` — the
information barrier that keeps the evaluator independent of the attack engine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "v1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────── enums / vocab ────────────────────────────────
class AttackCategory(str, Enum):
    prompt_injection = "prompt_injection"
    data_exfiltration = "data_exfiltration"
    state_corruption = "state_corruption"
    tool_misuse = "tool_misuse"
    denial_of_service = "denial_of_service"
    identity_role = "identity_role"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Outcome(str, Enum):
    """The Judge's verdict for one attempt."""

    success = "success"  # invariant falsified — the attack worked
    failure = "failure"  # the defense held
    partial = "partial"  # moved the needle; a mutation target
    error = "error"  # inconclusive (target unreachable, malformed)


class OwaspWeb(str, Enum):
    A01_broken_access_control = "A01:2021-Broken Access Control"
    A02_crypto_failures = "A02:2021-Cryptographic Failures"
    A03_injection = "A03:2021-Injection"
    A04_insecure_design = "A04:2021-Insecure Design"
    A05_misconfiguration = "A05:2021-Security Misconfiguration"
    A06_vulnerable_components = "A06:2021-Vulnerable and Outdated Components"
    A07_auth_failures = "A07:2021-Identification and Authentication Failures"
    A08_integrity_failures = "A08:2021-Software and Data Integrity Failures"
    A09_logging_failures = "A09:2021-Security Logging and Monitoring Failures"
    A10_ssrf = "A10:2021-SSRF"


class OwaspLlm(str, Enum):
    LLM01_prompt_injection = "LLM01:2025-Prompt Injection"
    LLM02_sensitive_disclosure = "LLM02:2025-Sensitive Information Disclosure"
    LLM03_supply_chain = "LLM03:2025-Supply Chain"
    LLM04_data_poisoning = "LLM04:2025-Data and Model Poisoning"
    LLM05_improper_output = "LLM05:2025-Improper Output Handling"
    LLM06_excessive_agency = "LLM06:2025-Excessive Agency"
    LLM08_vector_embedding = "LLM08:2025-Vector and Embedding Weaknesses"
    LLM10_unbounded_consumption = "LLM10:2025-Unbounded Consumption"


class _Versioned(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    schema_version: str = Field(default=SCHEMA_VERSION)


# ───────────────────── Orchestrator → Red Team ────────────────────────────
class CampaignDirective(_Versioned):
    """What the Orchestrator tells the Red Team to attack next."""

    directive_id: str
    category: AttackCategory
    subcategory: str = ""
    rationale: str = Field(description="Human-readable why-this-now (LLM-written).")
    target_invariant: str = Field(description="The invariant id this campaign tries to falsify.")
    max_attempts: int = Field(default=10, gt=0)
    seed_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)


# ───────────────────── Red Team → Judge ───────────────────────────────────
class TranscriptTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["attacker", "target"]
    content: str
    http_status: int | None = None
    raw: dict[str, Any] | None = None


class AttackAttempt(_Versioned):
    """One executed attack. The Judge reads only `transcript` (+ `expected_safe`
    and the invariant) — never `technique`/`intent`/`confidence` (info barrier)."""

    attempt_id: str
    directive_id: str
    seed_id: str | None = None
    category: AttackCategory
    subcategory: str = ""
    # --- attacker-private (Judge must NOT read these) ---
    technique: str = ""
    intent: str = ""
    attacker_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    generation: int = Field(default=0, ge=0, description="Mutation depth from the seed.")
    parent_attempt_id: str | None = None
    # --- shared / Judge-visible ---
    target_invariant: str
    expected_safe: str = Field(description="The safe behavior the target should exhibit.")
    transcript: list[TranscriptTurn]
    owasp_web: list[OwaspWeb] = Field(default_factory=list)
    owasp_llm: list[OwaspLlm] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)


# ───────────────────── Judge → Observability / Doc / Harness ──────────────
class Verdict(_Versioned):
    """The Judge's independent evaluation of one attempt."""

    verdict_id: str
    attempt_id: str
    outcome: Outcome
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    method: Literal["deterministic", "llm-adjudicator", "hybrid"] = "deterministic"
    rationale: str
    invariant_violated: str | None = None
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Machine signals: status, action, passed, matched strings."
    )
    is_regression_candidate: bool = False
    created_at: datetime = Field(default_factory=_now)


class ConfirmedExploit(_Versioned):
    """A Judge-confirmed success handed to Documentation and the harness."""

    exploit_id: str
    attempt_id: str
    verdict_id: str
    category: AttackCategory
    subcategory: str = ""
    severity: Severity
    target_invariant: str
    minimal_transcript: list[TranscriptTurn]
    expected_safe: str
    observed: str
    owasp_web: list[OwaspWeb] = Field(default_factory=list)
    owasp_llm: list[OwaspLlm] = Field(default_factory=list)
    target_version: str = "unknown"
    created_at: datetime = Field(default_factory=_now)


class RegressionCandidate(_Versioned):
    """A frozen, replayable case derived from a confirmed exploit."""

    case_id: str
    exploit_id: str
    category: AttackCategory
    request: dict[str, Any]
    # A deterministic assertion the harness re-checks on every target version.
    assertion: dict[str, Any] = Field(
        description="e.g. {'kind':'status_in','values':[401,403]} or "
        "{'kind':'answer_equals_withheld'}"
    )
    severity: Severity
    added_at: datetime = Field(default_factory=_now)


# ───────────────────── Documentation → Human / Store ──────────────────────
class VulnReport(_Versioned):
    """A professional vulnerability report — reproducible by an engineer who was
    not present when the exploit was found."""

    report_id: str
    exploit_id: str
    title: str
    severity: Severity
    category: AttackCategory
    status: Literal["draft", "published", "fixed", "wont-fix", "false-positive"] = "draft"
    summary: str
    clinical_impact: str
    reproduction: list[str] = Field(description="Numbered, copy-pasteable steps.")
    observed_behavior: str
    expected_behavior: str
    remediation: str
    fix_validation: str = ""
    owasp_web: list[OwaspWeb] = Field(default_factory=list)
    owasp_llm: list[OwaspLlm] = Field(default_factory=list)
    requires_human_approval: bool = False
    created_at: datetime = Field(default_factory=_now)


# ───────────────────── Typed error schemas (every agent) ──────────────────
class AgentError(_Versioned):
    """The one error envelope every agent emits for its known failure modes."""

    code: Literal[
        "target_unreachable",
        "budget_exceeded",
        "judge_timeout",
        "no_findings_in_window",
        "regression_detected",
        "auth_missing",
        "invalid_contract",
        "llm_unavailable",
    ]
    agent: str
    message: str
    retriable: bool = False
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_now)


__all__ = [
    "SCHEMA_VERSION",
    "AttackCategory",
    "Severity",
    "Outcome",
    "OwaspWeb",
    "OwaspLlm",
    "CampaignDirective",
    "TranscriptTurn",
    "AttackAttempt",
    "Verdict",
    "ConfirmedExploit",
    "RegressionCandidate",
    "VulnReport",
    "AgentError",
]
