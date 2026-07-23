"""CLI tests — the user-facing entry point (cli.py), above all the fail-closed
regression GATE. `adversaryforge regress` MUST exit non-zero when the gate is not
GREEN, or a CI merge gate silently lets a failed/errored/reappeared regression through
while the unit suite stays green — defeating the exact guarantee AS_BUILT advertises.
Also smoke-covers the status renderer (incl. the per-agent cost breakdown) and the
campaign renderer, so a dataclass/dict field rename is caught here, not in production.

Fully offline: run_regression / run_campaign are monkeypatched; the store points at a
temp DB via ADVERSARYFORGE_DATA_DIR.
"""
from __future__ import annotations

from types import SimpleNamespace

import adversaryforge.harness.regression as regression_mod
import adversaryforge.platform as platform_mod
from adversaryforge.cli import app
from adversaryforge.config import get_settings
from adversaryforge.observability.store import Store
from typer.testing import CliRunner

runner = CliRunner()


def _red_result():
    return {
        "target_version": "v-test", "all_passed": False,
        "total": 3, "passed": 1, "failed": 1, "skipped": 0, "errored": 1, "reappeared": 0,
        "details": [
            {"case_id": "c1", "category": "data_exfiltration", "passed": True, "result": "passed", "note": "ok"},
            {"case_id": "c2", "category": "prompt_injection", "passed": False, "result": "failed", "note": "leaked"},
            {"case_id": "c3", "category": "tool_misuse", "passed": False, "result": "errored", "note": "target down"},
        ],
    }


def _green_result():
    return {
        "target_version": "v-test", "all_passed": True,
        "total": 2, "passed": 2, "failed": 0, "skipped": 0, "errored": 0, "reappeared": 0,
        "details": [
            {"case_id": "c1", "category": "data_exfiltration", "passed": True, "result": "passed", "note": "ok"},
            {"case_id": "c2", "category": "prompt_injection", "passed": True, "result": "passed", "note": "ok"},
        ],
    }


def test_regress_exits_nonzero_when_gate_not_green(monkeypatch):
    async def _fake(settings=None):
        return _red_result()
    monkeypatch.setattr(regression_mod, "run_regression", _fake)
    result = runner.invoke(app, ["regress"])
    assert result.exit_code == 1               # the fail-closed CI gate actually BLOCKS
    assert "NOT GREEN" in result.stdout


def test_regress_exits_zero_when_green(monkeypatch):
    async def _fake(settings=None):
        return _green_result()
    monkeypatch.setattr(regression_mod, "run_regression", _fake)
    result = runner.invoke(app, ["regress"])
    assert result.exit_code == 0
    assert "GREEN" in result.stdout and "NOT GREEN" not in result.stdout


def test_status_renders_per_agent_cost(tmp_path, monkeypatch):
    monkeypatch.setenv("ADVERSARYFORGE_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    st = get_settings()
    store = Store(st.db_path)
    rid = store.start_run("http://t", "v", "test", False)
    store.log_cost(rid, "redteam", "hermes", 100, 20, 0.10)
    store.log_cost(rid, "judge", "claude", 200, 50, 0.05)
    store.close()

    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Cost by agent" in result.stdout
    assert "redteam" in result.stdout and "judge" in result.stdout


def test_campaign_renders_result_fields(monkeypatch):
    fake = SimpleNamespace(
        run_id="run_xyz", target_version="v9", authenticated=False,
        directive_rationale="probe unauth surface", total=5,
        by_outcome={"failure": 4, "success": 1}, successes=1, exploits_new=1,
        mutations_run=2, halted_no_signal=False,
        calibration_kappa=1.0, calibration_passed=True)

    async def _fake(**kwargs):
        return fake
    monkeypatch.setattr(platform_mod, "run_campaign", _fake)

    result = runner.invoke(app, ["campaign", "--limit", "1"])
    assert result.exit_code == 0
    assert "run_xyz" in result.stdout
    assert "successes: 1" in result.stdout
