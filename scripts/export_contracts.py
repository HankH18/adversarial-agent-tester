#!/usr/bin/env python
"""Export the versioned JSON-Schema contracts for every inter-agent message.

Each of the seven boundary-crossing models in `adversaryforge.contracts` is
serialized to `contracts/<ModelName>.v1.schema.json` — the canonical, on-disk
schema that both producers and consumers validate against. Regenerate whenever a
contract model changes (a breaking change also requires a version bump + a
migration note; see `contracts/README.md`).

Run:
    python scripts/export_contracts.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Make the package importable when run as `python scripts/export_contracts.py`
# (the script's own directory, not the repo root, is otherwise on sys.path[0]).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pydantic import BaseModel

from adversaryforge.contracts import (
    SCHEMA_VERSION,
    AgentError,
    AttackAttempt,
    CampaignDirective,
    ConfirmedExploit,
    RegressionCandidate,
    Verdict,
    VulnReport,
)

# The seven message types that cross an agent boundary, in producer order.
MODELS: tuple[type[BaseModel], ...] = (
    CampaignDirective,
    AttackAttempt,
    Verdict,
    ConfirmedExploit,
    RegressionCandidate,
    VulnReport,
    AgentError,
)

# Published contract version. Bumping this is a deliberate, breaking act.
VERSION = SCHEMA_VERSION  # "v1"

# Top-level keys we add on top of the pydantic-generated schema. The drift guard
# strips exactly these before comparing to `model.model_json_schema()`.
META_KEYS = ("$schema", "$id", "version")

CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"


def schema_id(model: type[BaseModel]) -> str:
    """Canonical `$id` for a contract, e.g. .../campaigndirective/v1."""
    return f"https://adversaryforge/contracts/{model.__name__.lower()}/{VERSION}"


def build_schema(model: type[BaseModel]) -> dict[str, Any]:
    """pydantic JSON Schema for `model`, prefixed with published metadata."""
    out: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id(model),
        "version": VERSION,
    }
    out.update(model.model_json_schema())
    return out


def schema_path(model: type[BaseModel]) -> Path:
    return CONTRACTS_DIR / f"{model.__name__}.{VERSION}.schema.json"


def main() -> int:
    CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        path = schema_path(model)
        path.write_text(json.dumps(build_schema(model), indent=2) + "\n")
        print(f"wrote {path.relative_to(CONTRACTS_DIR.parent)}")
    print(f"\n{len(MODELS)} contracts exported at version {VERSION}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
