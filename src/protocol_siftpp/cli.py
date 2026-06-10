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

from .agent_config import (
    DEEPSEEK_ANTHROPIC_BASE_URL,
    default_model,
    message_options,
    normalize_provider,
)
from .audit import AuditLogger, verify_chain
from .mcp_client import McpForensics
from .orchestrator import Orchestrator
from .schema import CaseReport, FindingStatus


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE pairs from an ignored local .env file."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lstrip("\ufeff")
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


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


def _llm_client(provider_name: str) -> AsyncAnthropic:
    provider = normalize_provider(provider_name)
    if provider == "deepseek":
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise SystemExit("Set DEEPSEEK_API_KEY or use --provider anthropic")
        return AsyncAnthropic(
            api_key=api_key,
            base_url=os.environ.get("DEEPSEEK_ANTHROPIC_BASE_URL", DEEPSEEK_ANTHROPIC_BASE_URL),
        )
    return AsyncAnthropic()


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
    _load_dotenv()
    evidence = Path(args.evidence)
    if not evidence.is_file():
        raise SystemExit(f"Evidence file not found: {evidence}")
    case_id = args.case_id or datetime.now(timezone.utc).strftime("case-%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else Path("analysis") / case_id
    out.mkdir(parents=True, exist_ok=True)

    audit = AuditLogger(out / "audit.jsonl", echo=True if args.echo else None)
    params = _server_params(evidence, out / "mcp-server.jsonl", args.offline)
    provider = normalize_provider(args.provider)
    model = args.model or default_model(provider)
    client = _llm_client(provider)

    async with McpForensics(params) as mcp:
        orch = Orchestrator(
            client,
            mcp,
            audit,
            max_iterations=args.max_iterations,
            model=model,
            model_kwargs=message_options(provider),
        )
        report = await orch.run(case_id=case_id)

    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    ok, n = verify_chain(out / "audit.jsonl")
    print(report.summary)
    print(f"audit log: {n} records, hash chain {'OK' if ok else 'BROKEN'}")
    print(f"outputs written to {out}/")


def main() -> None:
    _load_dotenv()
    p = argparse.ArgumentParser(
        prog="siftpp-investigate",
        description="Self-verifying autonomous DFIR investigation of a memory image.",
    )
    p.add_argument("--evidence", required=True, help="Path to the memory image")
    p.add_argument("--out", help="Output directory (default: analysis/<case-id>)")
    p.add_argument("--case-id", help="Case identifier")
    p.add_argument("--max-iterations", type=int, default=3, help="Self-correction rounds")
    p.add_argument("--offline", action="store_true", help="No Volatility symbol downloads")
    p.add_argument(
        "--echo",
        action="store_true",
        help="Stream one line per audit event (tool calls, findings, reviews) to stderr",
    )
    p.add_argument(
        "--provider",
        default=os.environ.get("SIFTPP_LLM_PROVIDER", "anthropic"),
        choices=["anthropic", "deepseek"],
        help="LLM provider (default: env SIFTPP_LLM_PROVIDER or anthropic)",
    )
    p.add_argument("--model", help="Override model name (default depends on provider)")
    asyncio.run(_run(p.parse_args()))


if __name__ == "__main__":
    main()
