"""The adversarial self-correction loop: Investigator -> Skeptic -> re-investigate.

This is the core differentiator (judging criteria #1 autonomous self-correction,
#2 catching hallucinations). Everything is recorded to a single tamper-evident
audit log: every model call (token usage), tool call (command + output hash),
inter-agent message, iteration, finding, and review.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from .agent_config import (
    ANTHROPIC_MODEL,
    DEFAULT_MAX_ITERATIONS,
    MAX_TOKENS,
    MAX_TOOL_RESULT_CHARS,
    MAX_TURNS_PER_AGENT,
    message_options,
)
from .audit import AuditLogger
from .client_tools import SUBMIT_FINDING_TOOL, SUBMIT_REVIEW_TOOL
from .prompts import (
    INITIAL_INSTRUCTION,
    INVESTIGATOR_SYSTEM,
    SKEPTIC_SYSTEM,
    render_reinvestigation,
    render_review_request,
)
from .schema import (
    CaseReport,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    SkepticReview,
)

# execute_tool(name, input) -> (content_for_model, is_error)
ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[tuple[str, bool]]]


async def _agent_loop(
    client: Any,
    *,
    system: str,
    tools: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    audit: AuditLogger,
    agent: str,
    execute_tool: ToolExecutor,
    model: str,
    model_kwargs: dict[str, Any],
    max_turns: int = MAX_TURNS_PER_AGENT,
) -> None:
    """Manual agentic tool-use loop for one agent activation."""
    for _ in range(max_turns):
        resp = await client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system,
            tools=tools,
            messages=messages,
            **model_kwargs,
        )
        u = resp.usage
        audit.log(
            "model_call",
            agent=agent,
            stop_reason=resp.stop_reason,
            input_tokens=getattr(u, "input_tokens", None),
            output_tokens=getattr(u, "output_tokens", None),
            cache_read_input_tokens=getattr(u, "cache_read_input_tokens", None),
            cache_creation_input_tokens=getattr(u, "cache_creation_input_tokens", None),
        )
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            break
        tool_results = []
        for block in resp.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            content, is_error = await execute_tool(block.name, dict(block.input or {}))
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": content[:MAX_TOOL_RESULT_CHARS],
                    "is_error": is_error,
                }
            )
        messages.append({"role": "user", "content": tool_results})


def _excerpt(result: dict[str, Any], limit: int = 400) -> str:
    if result.get("result") is not None:
        return json.dumps(result["result"], default=str)[:limit]
    return str(result.get("result_text", ""))[:limit]


class Orchestrator:
    def __init__(
        self,
        anthropic_client: Any,
        mcp: Any,
        audit: AuditLogger,
        *,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        model: str = ANTHROPIC_MODEL,
        model_kwargs: dict[str, Any] | None = None,
    ):
        self.client = anthropic_client
        self.mcp = mcp
        self.audit = audit
        self.max_iterations = max_iterations
        self.model = model
        self.model_kwargs = model_kwargs if model_kwargs is not None else message_options("anthropic")
        self.findings: list[Finding] = []
        self.evidence_by_tool: dict[str, list[Evidence]] = {}
        self._agent = "investigator"

    async def _exec_mcp(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        try:
            result = await self.mcp.call(name, args)
        except Exception as exc:  # surface to the model so it can adapt
            return f"Tool {name} failed: {exc}", True
        sha = result.get("output_sha256")
        self.audit.tool_call(
            agent=self._agent,
            tool=name,
            command=result.get("command", [name]),
            output_sha256=sha or "",
            output_bytes=result.get("output_bytes", 0),
            duration_ms=result.get("duration_ms", 0),
            exit_code=result.get("exit_code", 0),
            evidence_sha256=result.get("evidence_sha256"),
        )
        if sha:
            self.evidence_by_tool.setdefault(name, []).append(
                Evidence(
                    tool=name,
                    command=result.get("command", [name]),
                    output_excerpt=_excerpt(result),
                    output_sha256=sha,
                    output_bytes=result.get("output_bytes", 0),
                )
            )
        is_error = result.get("exit_code", 0) not in (0, None)
        return json.dumps(result, default=str), is_error

    def _record_finding(self, args: dict[str, Any], iteration: int) -> Finding:
        evidence: list[Evidence] = []
        for tool in args.get("cited_tools", []):
            evs = self.evidence_by_tool.get(tool)
            if evs:
                evidence.append(evs[-1])
        try:
            severity = Severity(args.get("severity", "medium"))
        except ValueError:
            severity = Severity.medium
        finding = Finding(
            claim=args["claim"],
            severity=severity,
            confidence=float(args.get("confidence", 0.5)),
            mitre_attack=args.get("mitre_attack", []),
            evidence=evidence,
            iteration=iteration,
            status=FindingStatus.draft,
        )
        self.findings.append(finding)
        self.audit.log(
            "finding_submitted",
            agent="investigator",
            finding_id=finding.id,
            claim=finding.claim,
            severity=severity.value,
            confidence=finding.confidence,
            cited_tools=args.get("cited_tools", []),
            rationale=args.get("rationale", ""),
        )
        return finding

    async def _investigate(self, instruction: str, iteration: int) -> None:
        self._agent = "investigator"
        tools = self.mcp.anthropic_tools + [SUBMIT_FINDING_TOOL]
        messages = [{"role": "user", "content": instruction}]

        async def execute(name: str, args: dict[str, Any]) -> tuple[str, bool]:
            if name == "submit_finding":
                f = self._record_finding(args, iteration)
                return f"Recorded finding {f.id}.", False
            return await self._exec_mcp(name, args)

        await _agent_loop(
            self.client,
            system=INVESTIGATOR_SYSTEM,
            tools=tools,
            messages=messages,
            audit=self.audit,
            agent="investigator",
            execute_tool=execute,
            model=self.model,
            model_kwargs=self.model_kwargs,
        )

    async def _review(self, finding: Finding) -> None:
        self._agent = "skeptic"
        self.audit.agent_message(
            sender="investigator",
            recipient="skeptic",
            summary=f"Verify {finding.id}: {finding.claim[:120]}",
        )
        tools = self.mcp.anthropic_tools + [SUBMIT_REVIEW_TOOL]
        messages = [{"role": "user", "content": render_review_request(finding)}]
        holder: dict[str, SkepticReview] = {}

        async def execute(name: str, args: dict[str, Any]) -> tuple[str, bool]:
            if name == "submit_review":
                try:
                    status = FindingStatus(args["status"])
                except (KeyError, ValueError):
                    return "status must be confirmed | inferred | refuted", True
                holder["review"] = SkepticReview(
                    status=status,
                    confidence=float(args.get("confidence", 0.5)),
                    refutation_attempt=args.get("refutation_attempt", ""),
                    rationale=args.get("rationale", ""),
                )
                return "Recorded review.", False
            return await self._exec_mcp(name, args)

        await _agent_loop(
            self.client,
            system=SKEPTIC_SYSTEM,
            tools=tools,
            messages=messages,
            audit=self.audit,
            agent="skeptic",
            execute_tool=execute,
            model=self.model,
            model_kwargs=self.model_kwargs,
        )

        review = holder.get("review")
        if review is None:  # skeptic never submitted -> treat as unverified inference
            review = SkepticReview(
                status=FindingStatus.inferred,
                confidence=min(finding.confidence, 0.4),
                refutation_attempt="no verdict returned",
                rationale="Skeptic did not submit a review; downgraded to inferred.",
            )
        finding.review = review
        finding.status = review.status
        finding.confidence = review.confidence
        finding.updated_at = datetime.now(timezone.utc)
        self.audit.log(
            "review_submitted",
            agent="skeptic",
            finding_id=finding.id,
            status=review.status.value,
            confidence=review.confidence,
        )
        self.audit.agent_message(
            sender="skeptic",
            recipient="investigator",
            summary=f"{finding.id}: {review.status.value} (confidence {review.confidence:.2f})",
        )

    async def run(self, case_id: str | None = None) -> CaseReport:
        meta = await self.mcp.call("evidence_metadata", {})
        evidence_path = meta.get("path", "unknown")
        evidence_sha = meta.get("sha256", "")
        self.audit.log("run_start", evidence_path=evidence_path, evidence_sha256=evidence_sha)

        await self._investigate(INITIAL_INSTRUCTION, iteration=0)

        corrections_run = 0
        for review_round in range(1, self.max_iterations + 1):
            pending = [f for f in self.findings if f.review is None]
            if not pending:
                break
            redo: list[Finding] = []
            for f in pending:
                await self._review(f)
                if f.needs_reinvestigation():
                    redo.append(f)
            if not redo or review_round == self.max_iterations:
                break
            corrections_run += 1
            self.audit.iteration(
                n=corrections_run,
                reason=f"{len(redo)} finding(s) refuted/low-confidence -> re-investigate",
            )
            await self._investigate(render_reinvestigation(redo), iteration=corrections_run)

        # Review any findings produced in the final iteration.
        for f in [f for f in self.findings if f.review is None]:
            await self._review(f)

        integrity = await self.mcp.call("verify_evidence_integrity", {})
        confirmed = [f for f in self.findings if f.status == FindingStatus.confirmed]
        self.audit.log(
            "run_end",
            findings=len(self.findings),
            confirmed=len(confirmed),
            evidence_unchanged=integrity.get("unchanged"),
        )

        return CaseReport(
            case_id=case_id or datetime.now(timezone.utc).strftime("case-%Y%m%d-%H%M%S"),
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha,
            findings=self.findings,
            iterations_run=corrections_run,
            summary=(
                f"{len(confirmed)} confirmed of {len(self.findings)} findings; "
                f"{corrections_run} self-correction iteration(s); "
                f"evidence integrity {'verified' if integrity.get('unchanged') else 'FAILED'}."
            ),
        )
