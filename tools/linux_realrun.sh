#!/usr/bin/env bash
# Full autonomous DeepSeek investigation on Linux (real case, paid).
# Writes to analysis/srl-2018-linux (separate from the documented Windows run).
# Credentials come from the repo-root .env (DEEPSEEK_API_KEY). Run after
# tools/linux_volcheck.sh has copied the image. Progress -> analysis/linux-realrun.log
set -uo pipefail

for p in "$HOME/.local/bin" "$HOME/.cargo/bin" /usr/local/bin; do
  [ -x "$p/uv" ] && export PATH="$p:$PATH"
done
command -v uv >/dev/null || { echo "uv not found"; exit 3; }

cd "$(dirname "$0")/.." || exit 3
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$HOME/siftpp-venv-linux}"

IMG="$HOME/ev/base-file-memory.img"
[ -f "$IMG" ] || { echo "image missing; run tools/linux_volcheck.sh first"; exit 4; }

mkdir -p analysis
LOG=analysis/linux-realrun.log
echo "start $(date -u)" > "$LOG"
uv run siftpp-investigate \
  --provider deepseek \
  --evidence "$IMG" \
  --out analysis/srl-2018-linux \
  --case-id srl-2018-linux \
  --max-iterations 3 >> "$LOG" 2>&1
rc=$?
echo "REALRUN rc=$rc $(date -u)" >> "$LOG"
echo "realrun done rc=$rc"
