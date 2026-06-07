#!/usr/bin/env bash
# Pre-flight for the Linux real run: copy the evidence image to the WSL native
# disk (fast reads) and confirm Volatility resolves symbols on Linux. No API key,
# no DeepSeek cost. Writes results to analysis/linux-volcheck.txt.
set -uo pipefail

for p in "$HOME/.local/bin" "$HOME/.cargo/bin" /usr/local/bin; do
  [ -x "$p/uv" ] && export PATH="$p:$PATH"
done
command -v uv >/dev/null || { echo "uv not found"; exit 3; }

cd "$(dirname "$0")/.." || exit 3
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$HOME/siftpp-venv-linux}"

SRC="evidence/srl-2018-base-file-memory/extracted/base-file-memory.img"
mkdir -p "$HOME/ev"
IMG="$HOME/ev/base-file-memory.img"
[ -f "$IMG" ] || cp "$SRC" "$IMG"

mkdir -p analysis
{
  echo "OS: $(uname -srm)"
  echo "IMG: $IMG ($(stat -c%s "$IMG") bytes)"
  echo "sha256: $(sha256sum "$IMG" | cut -d' ' -f1)"
  echo "(expected: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd)"
  echo "--- windows.info (online symbols allowed) ---"
  if uv run vol -q -r json -f "$IMG" windows.info > /tmp/info.json 2>/tmp/info.err; then
    head -c 1500 /tmp/info.json; echo; echo "VOL_INFO_OK"
  else
    echo "VOL_INFO_FAILED"; tail -25 /tmp/info.err
  fi
} > analysis/linux-volcheck.txt 2>&1
echo "volcheck done rc=$?"
