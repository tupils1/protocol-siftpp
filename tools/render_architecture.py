"""Render the Mermaid diagram in docs/ARCHITECTURE.md to docs/architecture.png.

Uses the mermaid.ink rendering service (no local Chromium needed). Run:
    uv run python tools/render_architecture.py
"""

from __future__ import annotations

import base64
import json
import re
import urllib.request
import zlib
from pathlib import Path

SRC = Path("docs/ARCHITECTURE.md")
OUT = Path("docs/architecture.png")


def extract_mermaid(md: str) -> str:
    m = re.search(r"```mermaid\n(.*?)```", md, re.S)
    if not m:
        raise SystemExit("no ```mermaid block found in docs/ARCHITECTURE.md")
    return m.group(1).strip()


def mermaid_ink_url(graph: str) -> str:
    state = {"code": graph, "mermaid": {"theme": "default"}}
    raw = json.dumps(state).encode("utf-8")
    packed = base64.urlsafe_b64encode(zlib.compress(raw, 9)).decode("ascii")
    return f"https://mermaid.ink/img/pako:{packed}?type=png&bgColor=FFFFFF"


def main() -> None:
    graph = extract_mermaid(SRC.read_text(encoding="utf-8"))
    url = mermaid_ink_url(graph)
    req = urllib.request.Request(url, headers={"User-Agent": "Protocol-SIFT++/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    if not data.startswith(b"\x89PNG"):
        raise SystemExit(f"mermaid.ink did not return a PNG (got {data[:40]!r})")
    OUT.write_bytes(data)
    print(f"wrote {OUT} ({len(data):,} bytes)")


if __name__ == "__main__":
    main()
