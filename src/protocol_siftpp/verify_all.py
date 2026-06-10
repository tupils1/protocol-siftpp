"""One command that proves every claim - for reviewers and the demo video.

    uv run siftpp-verify

Runs the test suite, verifies every committed audit hash chain, and runs the
live spoliation-resistance + tamper-evidence proofs against the real read-only MCP
server. Prints a checklist and exits non-zero if anything fails. The forensic
proofs need NO API key.
"""

from __future__ import annotations

import asyncio
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

from .audit import verify_chain
from .mcp_client import McpForensics
from .spoliation_test import _server_params, assess_spoliation
from .tamper_test import run_tamper_test

EXAMPLES = Path("docs/examples")
AUDITS = [
    ("SANS srl-2018 (Windows)", EXAMPLES / "srl-2018-base-file-memory" / "audit.jsonl"),
    ("SANS srl-2018 (Linux)", EXAMPLES / "srl-2018-linux" / "audit.jsonl"),
    ("M57 Pat (public case)", EXAMPLES / "m57-pat-2009-12-05" / "audit.jsonl"),
    ("SANS srl-2018 (demo-video run)", EXAMPLES / "srl-2018-live" / "audit.jsonl"),
]


def _row(ok: bool | None, label: str, detail: str = "") -> bool | None:
    tag = "[PASS]" if ok else ("[SKIP]" if ok is None else "[FAIL]")
    print(f"  {tag}  {label}" + (f"  -  {detail}" if detail else ""))
    return ok


async def _spoliation_passed() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        evidence = out / "synthetic-evidence.bin"
        evidence.write_bytes(b"SYNTHETIC EVIDENCE\n" * 64)
        async with McpForensics(_server_params(evidence, out / "mcp.jsonl")) as mcp:
            r = await assess_spoliation(mcp)
    return bool(r["passed"]), (
        f"{r['attempts_refused']}/{r['attempts_total']} destructive attempts refused, "
        f"evidence unchanged={r['evidence_unchanged']}"
    )


def main() -> None:
    print("Protocol SIFT++ - verify_all\n")
    results: list[bool] = []

    # 1) unit tests (skips gracefully where dev deps aren't installed, e.g. --no-dev)
    if importlib.util.find_spec("pytest") is None:
        _row(None, "unit tests", "pytest not installed (uv sync installs it; --no-dev skips)")
    else:
        proc = subprocess.run([sys.executable, "-m", "pytest", "-q"], capture_output=True, text=True)
        tail = next((ln for ln in reversed(proc.stdout.splitlines()) if ln.strip()), "")
        results.append(_row(proc.returncode == 0, "unit tests", tail))

    # 2) audit hash chains (committed examples - work on a fresh clone)
    for label, path in AUDITS:
        if not path.is_file():
            _row(None, f"audit chain - {label}", f"{path} not found")
            continue
        ok, n = verify_chain(path)
        results.append(_row(ok, f"audit chain - {label}", f"verify_chain -> ({ok}, {n})"))

    # 3) spoliation resistance (live read-only MCP server, no key)
    try:
        ok, detail = asyncio.run(_spoliation_passed())
        results.append(_row(ok, "spoliation resistance", detail))
    except Exception as exc:  # surface, don't crash the checklist
        results.append(_row(False, "spoliation resistance", f"{type(exc).__name__}: {exc}"))

    # 4) tamper-evidence (edit one audit record -> chain breaks)
    audit = next((p for _, p in AUDITS if p.is_file()), None)
    if audit is None:
        _row(None, "tamper-evidence", "no example audit found")
    else:
        with tempfile.TemporaryDirectory() as td:
            r = run_tamper_test(audit, Path(td))
        results.append(_row(bool(r.get("passed")), "tamper-evidence",
                            f"edit detected at record {r.get('break_detected_at_record')}"))

    print()
    if results and all(results):
        print("==== ALL CHECKS PASSED ====")
        raise SystemExit(0)
    print("==== SOME CHECKS FAILED ====")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
