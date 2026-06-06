#!/usr/bin/env bash
# Linux / SANS SIFT Workstation portability smoke for Protocol SIFT++.
# No API key needed: runs the test suite, the deterministic demo, and the
# spoliation-resistance test. Writes results to analysis/linux-smoke.txt.
#
#   bash tools/linux_smoke.sh
set -uo pipefail

for p in "$HOME/.local/bin" "$HOME/.cargo/bin" /usr/local/bin; do
  [ -x "$p/uv" ] && export PATH="$p:$PATH"
done
command -v uv >/dev/null || { echo "uv not found on PATH ($PATH)"; exit 3; }

cd "$(dirname "$0")/.." || exit 3
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$HOME/siftpp-venv-linux}"
mkdir -p analysis
out=analysis/linux-smoke.txt

{
  echo "OS: $(uname -srm)"
  echo "uv: $(command -v uv) ($(uv --version))"
  echo "PY: $(uv run python --version)"
  echo "--- pytest ---"; uv run pytest -q
  echo "--- ruff ---"; uv run ruff check src tests
  echo "--- demo ---"; uv run siftpp-demo --out /tmp/siftpp-demo
  head -c 1048576 /dev/urandom > /tmp/siftpp-syn.bin
  echo "--- spoliation ---"; uv run siftpp-spoliation-test --evidence /tmp/siftpp-syn.bin --out /tmp/siftpp-spol
  echo "SMOKE_DONE"
} > "$out" 2>&1
rc=$?
echo "wrote $out (rc=$rc)"
exit $rc
