"""`siftpp-investigate` - run the self-verifying DFIR investigation on a memory image.

Spawns the read-only MCP server, runs the Investigator/Skeptic self-correction
loop, and writes report.json, report.md, and a tamper-evident audit.jsonl.
Requires Anthropic credentials in the environment (ANTHROPIC_API_KEY or an
`ant auth login` profile).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from anthropic import AsyncAnthropic
from mcp import StdioServerParameters

from .audit import AuditLogger, verify_chain
from .mcp_client import McpForensics
from .orchestrator import Orchestrator
from .schema import CaseReport, FindingStatus


def _server_params(evidence: Path, server_audit: Path, offline: bool) -> StdioServerParameters:
    env = {
        **os.environ,
        "SIFTPP_EVIDENCE": str(evidence),
        "SIFTPP_AUDIT_LOG": str(server_audit),
    }
    if offline:
        env["SIFTPP_VOL_OFFLINE"] = "1"
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "protocol_siftpp.mcp_server.server"],
        env=env,
    )


def render_markdown(report: CaseReport) -> str:
    order = [FindingStatus.confirmed, FindingStatus.inferred, FindingStatus.refuted, FindingStatus.draft]
    lines = [
        f"# Incident Report — {report.case_id}",
        "",
        f"- Evidence: `{report.evidence_path}`",
        f"- Evidence sha256: `{report.evidence_sha256}`",
        f"- Self-correction iterations: {report.iterations_run}",
        f"- Summary: {report.summary}",
        "",
    ]
    for status in order:
        group = report.by_status(status)
        if not group:
            continue
        lines.append(f"## {status.value.capitalize()} ({len(group)})")
        for f in group:
            lines.append(f"### [{f.severity.value}] {f.claim}")
            lines.append(f"- confidence: {f.confidence:.2f}")
            if f.mitre_attack:
                lines.append(f"- ATT&CK: {', '.join(f.mitre_attack)}")
            if f.review:
                lines.append(f"- Skeptic: {f.review.rationale}")
            for e in f.evidence:
                lines.append(f"- evidence: `{e.tool}` (sha256 `{e.output_sha256[:16]}…`)")
            lines.append("")
    return "\n".join(lines)


async def _run(args: argparse.Namespace) -> None:
    evidence = Path(args.evidence)
    if not evidence.is_file():
        raise SystemExit(f"Evidence file not found: {evidence}")
    case_id = args.case_id or datetime.now(timezone.utc).strftime("case-%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else Path("analysis") / case_id
    out.mkdir(parents=True, exist_ok=True)

    audit = AuditLogger(out / "audit.jsonl")
    params = _server_params(evidence, out / "mcp-server.jsonl", args.offline)
    client = AsyncAnthropic()

    async with McpForensics(params) as mcp:
        orch = Orchestrator(client, mcp, audit, max_iterations=args.max_iterations)
        report = await orch.run(case_id=case_id)

    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    ok, n = verify_chain(out / "audit.jsonl")
    print(report.summary)
    print(f"audit log: {n} records, hash chain {'OK' if ok else 'BROKEN'}")
    print(f"outputs written to {out}/")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="siftpp-investigate",
        description="Self-verifying autonomous DFIR investigation of a memory image.",
    )
    p.add_argument("--evidence", required=True, help="Path to the memory image")
    p.add_argument("--out", help="Output directory (default: analysis/<case-id>)")
    p.add_argument("--case-id", help="Case identifier")
    p.add_argument("--max-iterations", type=int, default=3, help="Self-correction rounds")
    p.add_argument("--offline", action="store_true", help="No Volatility symbol downloads")
    asyncio.run(_run(p.parse_args()))


if __name__ == "__main__":
    main()
