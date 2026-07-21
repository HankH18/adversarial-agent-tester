"""Regression & Validation Harness.

Re-runs every confirmed exploit as a frozen, replayable case and asks the *same*
independent Judge whether the invariant it once falsified still holds. See
``adversaryforge.harness.regression`` for the design rationale (why a PASS here is
a genuine fix and not mere behavioral drift).
"""
from __future__ import annotations

from adversaryforge.harness.regression import (
    detect_cross_category_regression,
    run_regression,
)

__all__ = ["run_regression", "detect_cross_category_regression"]
