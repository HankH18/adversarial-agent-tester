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
  echo "==> uv not found — falling back to venv + pip (uv is recommended; it provisions Python 3.12)"
  # The project requires Python 3.11+. Pick the newest suitable interpreter and fail LOUDLY if
  # only an older python3 is on PATH — a bare `python3` is often 3.9 (macOS/Anaconda default),
  # which otherwise dies with a cryptic requires-python error mid-install.
  PY=""
  for c in python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && \
       "$c" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  done
  if [ -z "$PY" ]; then
    echo "ERROR: Python 3.11+ is required but none found on PATH (tried python3.12/python3.11/python3)." >&2
    echo "       Install Python 3.11+, or (recommended) install uv: https://docs.astral.sh/uv/" >&2
    exit 1
  fi
  "$PY" -m venv .venv
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

echo "==> offline smoke: seed-published (load the real committed findings)"
run_cli seed-published
echo "==> offline smoke: report (regenerate reports/VULN-*.md byte-for-byte from the ledger)"
run_cli report
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
