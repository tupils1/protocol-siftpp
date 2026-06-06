"""Deterministic local demo for the Protocol SIFT++ self-correction loop.

This is a development smoke test, not a substitute for the final SANS case-data
run. It uses the real Orchestrator with a scripted model and replayed read-only
tool outputs so the core differentiator can be demonstrated without API keys,
Volatility symbols, or a downloaded memory image.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLogger, verify_chain
from .cli import render_markdown
from .orchestrator import Orchestrator
from .schema import CaseReport, sha256_hex

DEMO_EVIDENCE_BYTES = (
    b"Protocol SIFT++ deterministic demo evidence.\n"
    b"This is not a forensic image; it only anchors the integrity checks.\n"
)


class _Block:
    def __init__(
        self,
        type: str,
        *,
        text: str | None = None,
        name: str | None = None,
        input: dict[str, Any] | None = None,
        id: str | None = None,
    ):
        self.type = type
        self.text = text
        self.name = name
        self.input = input or {}
        self.id = id


class _Usage:
    input_tokens = 100
    output_tokens = 50
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0


class _Resp:
    def __init__(self, content: list[_Block], stop_reason: str):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Usage()


class _Messages:
    def __init__(self, investigator: list[_Resp], skeptic: list[_Resp]):
        self.scripts = {"investigator": investigator, "skeptic": skeptic}

    async def create(self, *, system: str, **_: Any) -> _Resp:
        agent = "skeptic" if "Skeptic" in system else "investigator"
        try:
            return self.scripts[agent].pop(0)
        except IndexError as exc:
            raise RuntimeError(f"demo script exhausted for {agent}") from exc


class ScriptedAnthropic:
    def __init__(self) -> None:
        self.messages = _Messages(_investigator_script(), _skeptic_script())


def _finding_call(
    *,
    id: str,
    claim: str,
    severity: str,
    confidence: float,
    tools: list[str],
    rationale: str,
    mitre_attack: list[str] | None = None,
) -> _Block:
    return _Block(
        "tool_use",
        name="submit_finding",
        id=id,
        input={
            "claim": claim,
            "severity": severity,
            "confidence": confidence,
            "cited_tools": tools,
            "mitre_attack": mitre_attack or [],
            "rationale": rationale,
        },
    )


def _review_call(
    *,
    id: str,
    status: str,
    confidence: float,
    refutation_attempt: str,
    rationale: str,
) -> _Block:
    return _Block(
        "tool_use",
        name="submit_review",
        id=id,
        input={
            "status": status,
            "confidence": confidence,
            "refutation_attempt": refutation_attempt,
            "rationale": rationale,
        },
    )


def _investigator_script() -> list[_Resp]:
    return [
        _Resp([_Block("tool_use", name="vol_pslist", id="i-tool-1")], "tool_use"),
        _Resp(
            [_Block("tool_use", name="vol_malfind", id="i-tool-2", input={"pid": 1640})],
            "tool_use",
        ),
        _Resp(
            [
                _finding_call(
                    id="i-finding-1",
                    claim="PID 1640 reader_sl.exe shows injected code.",
                    severity="high",
                    confidence=0.74,
                    tools=["vol_malfind"],
                    rationale="Initial pass over-interpreted the malfind check.",
                    mitre_attack=["T1055"],
                )
            ],
            "tool_use",
        ),
        _Resp([_Block("text", text="Initial investigation complete.")], "end_turn"),
        _Resp([_Block("tool_use", name="vol_cmdline", id="i-tool-3")], "tool_use"),
        _Resp([_Block("tool_use", name="vol_netscan", id="i-tool-4")], "tool_use"),
        _Resp(
            [
                _finding_call(
                    id="i-finding-2",
                    claim=(
                        "PID 1640 reader_sl.exe ran from a user Temp path and held an "
                        "external HTTPS connection to 203.0.113.50."
                    ),
                    severity="high",
                    confidence=0.83,
                    tools=["vol_cmdline", "vol_netscan"],
                    rationale=(
                        "cmdline shows a Temp launch path, and netscan ties the same "
                        "PID to the external connection."
                    ),
                    mitre_attack=["T1204", "T1105"],
                )
            ],
            "tool_use",
        ),
        _Resp([_Block("text", text="Re-investigation complete.")], "end_turn"),
    ]


def _skeptic_script() -> list[_Resp]:
    return [
        _Resp(
            [_Block("tool_use", name="vol_malfind", id="s-tool-1", input={"pid": 1640})],
            "tool_use",
        ),
        _Resp(
            [
                _review_call(
                    id="s-review-1",
                    status="refuted",
                    confidence=0.18,
                    refutation_attempt=(
                        "Re-ran vol_malfind for PID 1640 and looked for private RWX "
                        "or no-file-backed VAD evidence."
                    ),
                    rationale=(
                        "The replayed malfind output has no suspicious VAD rows for "
                        "PID 1640, so the injected-code claim is unsupported."
                    ),
                )
            ],
            "tool_use",
        ),
        _Resp([_Block("text", text="First finding refuted.")], "end_turn"),
        _Resp([_Block("tool_use", name="vol_cmdline", id="s-tool-2")], "tool_use"),
        _Resp([_Block("tool_use", name="vol_netscan", id="s-tool-3")], "tool_use"),
        _Resp(
            [
                _review_call(
                    id="s-review-2",
                    status="confirmed",
                    confidence=0.91,
                    refutation_attempt=(
                        "Cross-checked PID 1640 in command-line and network artifacts."
                    ),
                    rationale=(
                        "Both independent tool outputs support the narrower claim: "
                        "the same PID has the Temp-path command line and the external "
                        "connection."
                    ),
                )
            ],
            "tool_use",
        ),
        _Resp([_Block("text", text="Replacement finding confirmed.")], "end_turn"),
    ]


def _tool_schema(name: str, description: str, *, pid: bool = False) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    if pid:
        properties["pid"] = {"type": "integer", "minimum": 0}
    return {
        "name": name,
        "description": description,
        "input_schema": {"type": "object", "properties": properties},
    }


class ReplayMcp:
    anthropic_tools = [
        _tool_schema("vol_pslist", "Replay of windows.pslist."),
        _tool_schema("vol_malfind", "Replay of windows.malfind.", pid=True),
        _tool_schema("vol_cmdline", "Replay of windows.cmdline."),
        _tool_schema("vol_netscan", "Replay of windows.netscan."),
    ]

    def __init__(self, evidence_path: Path):
        self.evidence_path = evidence_path
        self.evidence_path.write_bytes(DEMO_EVIDENCE_BYTES)
        self.evidence_sha256 = sha256_hex(DEMO_EVIDENCE_BYTES)

    async def call(self, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        args = args or {}
        if name == "evidence_metadata":
            return {
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha256,
                "bytes": self.evidence_path.stat().st_size,
                "read_only": True,
            }
        if name == "verify_evidence_integrity":
            after = sha256_hex(self.evidence_path.read_bytes())
            return {
                "path": str(self.evidence_path),
                "sha256_before": self.evidence_sha256,
                "sha256_after": after,
                "unchanged": after == self.evidence_sha256,
            }
        if name == "vol_pslist":
            return self._tool_result(
                name,
                [{"PID": 1640, "PPID": 992, "ImageFileName": "reader_sl.exe"}],
            )
        if name == "vol_malfind":
            pid = args.get("pid")
            return self._tool_result(
                name,
                [] if pid == 1640 else [{"PID": 9999, "Protection": "PAGE_EXECUTE_READWRITE"}],
                pid=pid,
            )
        if name == "vol_cmdline":
            return self._tool_result(
                name,
                [
                    {
                        "PID": 1640,
                        "ImageFileName": "reader_sl.exe",
                        "CommandLine": (
                            "C:\\Users\\victim\\AppData\\Local\\Temp\\reader_sl.exe "
                            "--update"
                        ),
                    }
                ],
            )
        if name == "vol_netscan":
            return self._tool_result(
                name,
                [
                    {
                        "PID": 1640,
                        "Owner": "reader_sl.exe",
                        "LocalAddr": "10.0.2.15",
                        "LocalPort": 49722,
                        "ForeignAddr": "203.0.113.50",
                        "ForeignPort": 443,
                        "State": "ESTABLISHED",
                    }
                ],
            )
        raise ValueError(f"unknown replay tool: {name}")

    def _tool_result(
        self,
        tool: str,
        result: list[dict[str, Any]],
        *,
        pid: int | None = None,
    ) -> dict[str, Any]:
        plugin = f"windows.{tool[4:]}"
        command = ["vol", "-q", "-r", "json", "-f", str(self.evidence_path), plugin]
        if pid is not None:
            command += ["--pid", str(pid)]
        output = json.dumps(result, sort_keys=True).encode("utf-8")
        return {
            "tool": tool,
            "plugin": plugin,
            "command": command,
            "exit_code": 0,
            "timed_out": False,
            "evidence_sha256": self.evidence_sha256,
            "integrity_ok": True,
            "output_sha256": sha256_hex(output),
            "output_bytes": len(output),
            "duration_ms": 1,
            "row_count": len(result),
            "truncated": False,
            "result": result,
            "result_text": None,
            "stderr": "",
        }


@dataclass
class DemoResult:
    report: CaseReport
    out_dir: Path
    audit_ok: bool
    audit_records: int


async def run_demo(
    *,
    out: str | Path = "analysis/demo",
    case_id: str = "demo-self-correction",
    max_iterations: int = 3,
) -> DemoResult:
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLogger(out_dir / "audit.jsonl")
    evidence_path = out_dir / "demo-memory.raw"

    orchestrator = Orchestrator(
        ScriptedAnthropic(),
        ReplayMcp(evidence_path),
        audit,
        max_iterations=max_iterations,
    )
    report = await orchestrator.run(case_id=case_id)

    (out_dir / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    ok, n = verify_chain(out_dir / "audit.jsonl")
    return DemoResult(report=report, out_dir=out_dir, audit_ok=ok, audit_records=n)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="siftpp-demo",
        description="Run a deterministic local demo of the self-correction loop.",
    )
    parser.add_argument("--out", default="analysis/demo", help="Output directory")
    parser.add_argument("--case-id", default="demo-self-correction", help="Case identifier")
    parser.add_argument("--max-iterations", type=int, default=3, help="Correction budget")
    args = parser.parse_args()

    result = asyncio.run(
        run_demo(out=args.out, case_id=args.case_id, max_iterations=args.max_iterations)
    )
    print(result.report.summary)
    print(f"audit log: {result.audit_records} records, hash chain "
          f"{'OK' if result.audit_ok else 'BROKEN'}")
    print(f"outputs written to {result.out_dir}/")


if __name__ == "__main__":
    main()
