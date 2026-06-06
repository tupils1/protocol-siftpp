"""Protocol SIFT++ read-only forensic MCP server.

Exposes a curated set of READ-ONLY Volatility 3 operations as MCP tools. The
Investigator / Skeptic agents connect to this server over stdio; because the
server contains no write/dump/network tool, the agents cannot alter evidence.

Configuration via environment variables:
  SIFTPP_EVIDENCE      path to the memory image (required)
  SIFTPP_AUDIT_LOG     audit JSONL path (default: analysis/audit.jsonl)
  SIFTPP_AGENT         agent name recorded in the audit log (default: investigator)
  SIFTPP_VOL_OFFLINE   "1" to pass --offline to Volatility (no symbol downloads)

Run standalone:  uv run siftpp-mcp     (with SIFTPP_EVIDENCE set)
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from ..audit import AuditLogger
from .volatility import READ_ONLY_PLUGINS, EvidenceGuard, VolatilityRunner

mcp = FastMCP("protocol-siftpp-readonly")

_runner: VolatilityRunner | None = None


def _build_runner() -> VolatilityRunner:
    evidence = os.environ.get("SIFTPP_EVIDENCE")
    if not evidence:
        raise RuntimeError("Set SIFTPP_EVIDENCE to the path of the memory image")
    audit = AuditLogger(os.environ.get("SIFTPP_AUDIT_LOG", "analysis/audit.jsonl"))
    runner = VolatilityRunner(
        guard=EvidenceGuard.open(evidence),
        audit=audit,
        agent=os.environ.get("SIFTPP_AGENT", "investigator"),
        offline=os.environ.get("SIFTPP_VOL_OFFLINE") == "1",
    )
    runner.session_start()
    return runner


def get_runner() -> VolatilityRunner:
    global _runner
    if _runner is None:
        _runner = _build_runner()
    return _runner


def _dump(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


@mcp.tool()
def evidence_metadata() -> str:
    """Evidence path, size, acquisition sha256 (chain of custody), and the list
    of available read-only tools. Call this first."""
    r = get_runner()
    return _dump({
        "path": str(r.guard.path),
        "sha256": r.guard.sha256,
        "bytes": r.guard.size,
        "read_only": True,
        "tools": [{"name": p.tool, "summary": p.summary} for p in READ_ONLY_PLUGINS],
    })


@mcp.tool()
def vol_info() -> str:
    """windows.info: image OS build, architecture, KDBG. Run first to orient."""
    return _dump(get_runner().run("vol_info"))


@mcp.tool()
def vol_pslist() -> str:
    """windows.pslist: active processes from the EPROCESS list."""
    return _dump(get_runner().run("vol_pslist"))


@mcp.tool()
def vol_pstree() -> str:
    """windows.pstree: process tree with parent/child relationships."""
    return _dump(get_runner().run("vol_pstree"))


@mcp.tool()
def vol_psscan() -> str:
    """windows.psscan: pool-scan for processes; reveals hidden/terminated ones."""
    return _dump(get_runner().run("vol_psscan"))


@mcp.tool()
def vol_cmdline() -> str:
    """windows.cmdline: each process's command line."""
    return _dump(get_runner().run("vol_cmdline"))


@mcp.tool()
def vol_dlllist(pid: int | None = None) -> str:
    """windows.dlllist: loaded DLLs, optionally for a single PID."""
    return _dump(get_runner().run("vol_dlllist", pid=pid))


@mcp.tool()
def vol_malfind(pid: int | None = None) -> str:
    """windows.malfind: injected code (private RWX, no file backing), optionally one PID."""
    return _dump(get_runner().run("vol_malfind", pid=pid))


@mcp.tool()
def vol_netscan() -> str:
    """windows.netscan: network connections and sockets from the pool."""
    return _dump(get_runner().run("vol_netscan"))


@mcp.tool()
def vol_svcscan() -> str:
    """windows.svcscan: Windows services (spot persistence / malicious services)."""
    return _dump(get_runner().run("vol_svcscan"))


@mcp.tool()
def verify_evidence_integrity() -> str:
    """Re-hash the full evidence file and confirm it is byte-identical to
    acquisition (spoliation proof). Call this at the end of an investigation."""
    return _dump(get_runner().verify_integrity())


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
