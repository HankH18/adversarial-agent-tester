"""Doc-vs-code consistency guard — the recurring doc-drift class.

Load-bearing NUMBERS get quoted across the deliverable docs (`BUILD_LEDGER.md`,
`AS_BUILT.md`, `DEMO_SCRIPT.md`, the architecture packets): "7 schemas",
"23 seeds, 6 categories", the required error codes. When code or data changes but
a doc's count does not, the drift is silent and embarrassing in a review.

These tests derive the truth from code/files *at test time* — glob `contracts/`,
count `export_contracts.MODELS`, `len(AttackCategory)`, `SeedLibrary.load()`, the
target adapter's invariant registry — and, where a doc states a specific number,
grep the doc and compare against that live truth. Nothing here hardcodes the
answer as its own source: the `== 7` / `== 6` anchors are sanity guards on the
shape of the repo, and every doc comparison is code-vs-doc.

Fully offline: no ANTHROPIC_API_KEY, no session cookie.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import get_args

import yaml

from adversaryforge.contracts import AgentError, AttackCategory
from adversaryforge.redteam.seeds import SeedLibrary
from adversaryforge.target.adapter import agentforge_adapter

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CONTRACTS_DIR = _REPO_ROOT / "contracts"
_SEEDS_DIR = _REPO_ROOT / "evals" / "seeds"
_DOCS_DIR = _REPO_ROOT / "docs"

# Reuse the exact export logic so this guard can never disagree with the writer
# about the contract-model list (same import dance as tests/test_contracts.py).
sys.path.insert(0, str(_REPO_ROOT / "scripts"))
import export_contracts  # noqa: E402


# ── helpers ────────────────────────────────────────────────────────────────
def _doc_numbers(pattern: str) -> list[tuple[str, int]]:
    """Every integer captured by `pattern` (one group, IGNORECASE) across the
    markdown docs, tagged with its repo-relative source path."""
    rx = re.compile(pattern, re.IGNORECASE)
    out: list[tuple[str, int]] = []
    for doc in sorted(_DOCS_DIR.rglob("*.md")):
        for m in rx.finditer(doc.read_text(encoding="utf-8")):
            out.append((str(doc.relative_to(_REPO_ROOT)), int(m.group(1))))
    return out


def _raw_seed_ids() -> list[str]:
    """Seed ids straight from the YAML corpus, independent of the loader — so a
    loader that silently drops a case is detectable (code-vs-file)."""
    ids: list[str] = []
    for path in sorted(_SEEDS_DIR.glob("*.y*ml")):
        for raw in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            ids.append(raw["id"])
    return ids


# ── (1) contracts: one published schema per exported model ─────────────────
def test_published_schema_count_matches_exported_models():
    """`contracts/*.v1.schema.json` is exactly one file per `MODELS` entry."""
    schemas = sorted(_CONTRACTS_DIR.glob("*.v1.schema.json"))
    models = export_contracts.MODELS
    assert len(schemas) == len(models) == 7
    assert {p.name for p in schemas} == {
        f"{m.__name__}.v1.schema.json" for m in models
    }


def test_docs_agree_on_schema_count():
    """Every doc that quotes a published-schema count matches `len(MODELS)`."""
    truth = len(export_contracts.MODELS)
    # The negative lookbehind rejects the "12" in "Draft 2020-12 JSON Schema".
    claims = _doc_numbers(r"(?<![\d-])(\d+)\s+(?:JSON\s+)?schema")
    assert claims, "no doc states the published-schema count"
    for doc, n in claims:
        assert n == truth, f"{doc} says {n} schemas; export_contracts.MODELS has {truth}"


# ── (2) attack categories ──────────────────────────────────────────────────
def test_attack_category_count():
    """The enum defines six categories, and the seed corpus only uses declared
    ones (code-vs-file)."""
    assert len(AttackCategory) == 6
    valid = {c.value for c in AttackCategory}
    used = {
        s.category.value if hasattr(s.category, "value") else s.category
        for s in SeedLibrary.load().seeds
    }
    assert used <= valid, f"seeds use categories outside the enum: {sorted(used - valid)}"


# ── (3) seeds ──────────────────────────────────────────────────────────────
def test_seed_count_matches_loader_and_docs():
    """`SeedLibrary.load()` is the source of truth; it drops no YAML case, and
    every doc that quotes a seed count agrees with it."""
    loaded = SeedLibrary.load().seeds
    assert len(loaded) == len(_raw_seed_ids())  # loader drops nothing
    assert len({s.id for s in loaded}) == len(loaded)  # ids unique
    truth = len(loaded)
    claims = _doc_numbers(r"(?<![\d-])(\d+)\s+seeds?\b")
    assert claims, "no doc states the seed count"
    for doc, n in claims:
        assert n == truth, f"{doc} says {n} seeds; SeedLibrary.load() has {truth}"


def test_docs_agree_on_paired_seed_and_category_counts():
    """Docs phrase it as 'N seeds, M categories' together — both must match the
    live truth in the same breath (a precise, low-noise drift anchor)."""
    n_seeds = len(SeedLibrary.load().seeds)
    n_cats = len(AttackCategory)
    rx = re.compile(r"(\d+)\s+seeds?,\s+(\d+)\s+cat(?:egor(?:y|ies)|s)\b", re.IGNORECASE)
    found = False
    for doc in sorted(_DOCS_DIR.rglob("*.md")):
        rel = doc.relative_to(_REPO_ROOT)
        for m in rx.finditer(doc.read_text(encoding="utf-8")):
            found = True
            assert int(m.group(1)) == n_seeds, f"{rel}: {m.group(0)!r} vs {n_seeds} seeds"
            assert int(m.group(2)) == n_cats, f"{rel}: {m.group(0)!r} vs {n_cats} categories"
    assert found, "no doc states a paired 'N seeds, M categories' count"


# ── (4) error codes + invariant registry (countable code-vs-code) ──────────
def test_agent_error_required_codes_present():
    """The typed error envelope carries the required codes plus its extras; the
    five docs call 'required' must never silently disappear from the enum."""
    codes = set(get_args(AgentError.model_fields["code"].annotation))
    assert len(codes) == 8
    required = {
        "target_unreachable",
        "budget_exceeded",
        "judge_timeout",
        "no_findings_in_window",
        "regression_detected",
    }
    assert required <= codes, f"missing required error codes: {sorted(required - codes)}"


def test_invariant_registry_covers_every_seed():
    """The target adapter's invariant playbook is the registry every seed points
    at; no seed may reference an invariant the registry does not define."""
    invariants = agentforge_adapter("http://localhost:9999").invariants
    assert invariants, "target adapter declares no safety invariants"
    referenced = {s.target_invariant for s in SeedLibrary.load().seeds}
    missing = referenced - set(invariants)
    assert not missing, f"seeds reference invariants absent from the registry: {sorted(missing)}"
