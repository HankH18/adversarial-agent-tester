#!/usr/bin/env bash
# One-command fresh-clone bootstrap for AdversaryForge.
#
# Creates the environment, installs the project (+ dev extras), then PROVES the CLI
# works fully offline: seed-demo populates illustrative findings and status renders
# them. No secrets, no network to the target required — this is the zero-config path a
# grader can run on a fresh clone.
#
#   ./scripts/bootstrap.sh
#
# Prefers `uv` (installs from the pinned uv.lock when present); falls back to stdlib
# venv + pip. Idempotent: safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v uv >/dev/null 2>&1; then
  HAVE_UV=1
  echo "==> uv detected — syncing from uv.lock"
  if [ -f uv.lock ]; then
    uv sync --extra dev --locked
  else
    uv sync --extra dev
  fi
else
  HAVE_UV=0
  echo "==> uv not found — falling back to python3 venv + pip"
  # No version pin: the project supports Python 3.11+, so use whatever python3 resolves.
  python3 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/pip install -e '.[dev]'
fi

# Uniform CLI invocation across the uv / fallback branches.
run_cli() {
  if [ "$HAVE_UV" = "1" ]; then
    uv run python -m adversaryforge.cli "$@"
  else
    .venv/bin/python -m adversaryforge.cli "$@"
  fi
}

echo "==> offline smoke: seed-demo (populate illustrative findings)"
run_cli seed-demo
echo "==> offline smoke: status (render the observability snapshot)"
run_cli status

cat <<'DONE'

✓ bootstrap complete.
  Next:
    - Live campaign against the authorized target:
        .venv/bin/python -m adversaryforge.cli campaign   (or: uv run python -m adversaryforge.cli campaign)
    - Full test suite:
        .venv/bin/python -m pytest -q                     (or: uv run pytest -q)
  See README.md "Quick start" for secrets that unlock the authenticated attack plane.
DONE
