"""Finding schema for Protocol SIFT++ (DESIGN.md section 4).

Every claim the Investigator makes is a `Finding`. The Skeptic attaches a
`SkepticReview` and sets the final `status`. Each finding cites the exact
read-only tool executions (`Evidence`) that support it, so the report traces
back to specific commands and their output hashes.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(data: bytes | str) -> str:
    """sha256 helper shared by evidence + audit code."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    draft = "draft"          # proposed by the Investigator, not yet reviewed
    confirmed = "confirmed"  # evidence directly supports the claim
    inferred = "inferred"    # plausible, but not directly evidenced
    refuted = "refuted"      # contradicted / unsupported -> drop or re-investigate


INFERRED_REINVESTIGATION_THRESHOLD = 0.70


class Evidence(BaseModel):
    """A single read-only tool execution cited in support of a finding."""

    tool: str = Field(..., description="MCP tool name, e.g. 'vol3.pslist'")
    command: list[str] = Field(..., description="Exact argv that was executed")
    output_excerpt: str = Field(..., description="Human-readable slice of the output")
    output_sha256: str = Field(..., description="sha256 of the FULL tool output")
    output_bytes: int = Field(..., ge=0)
    ran_at: datetime = Field(default_factory=_utcnow)


class SkepticReview(BaseModel):
    """The Skeptic's adversarial review of one finding."""

    status: FindingStatus
    confidence: float = Field(..., ge=0.0, le=1.0)
    refutation_attempt: str = Field(
        ..., description="What the Skeptic checked while trying to DISPROVE the claim"
    )
    rationale: str = Field(..., description="Why it landed on this status / confidence")
    reviewed_at: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    claim: str
    severity: Severity = Severity.medium
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.draft
    evidence: list[Evidence] = Field(default_factory=list)
    mitre_attack: list[str] = Field(
        default_factory=list, description="ATT&CK technique IDs, e.g. ['T1055']"
    )
    review: SkepticReview | None = None
    iteration: int = Field(0, description="Self-correction round this finding belongs to")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    @field_validator("mitre_attack")
    @classmethod
    def _normalize_techniques(cls, v: list[str]) -> list[str]:
        return [t.strip().upper() for t in v if t.strip()]

    def needs_reinvestigation(self) -> bool:
        """A refuted or weakly inferred finding re-enters the Investigator."""
        if self.status == FindingStatus.refuted:
            return True
        if (
            self.status == FindingStatus.inferred
            and self.confidence < INFERRED_REINVESTIGATION_THRESHOLD
        ):
            return True
        return self.confidence < 0.5


class CaseReport(BaseModel):
    case_id: str
    evidence_path: str
    evidence_sha256: str
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""
    iterations_run: int = 0
    generated_at: datetime = Field(default_factory=_utcnow)

    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.confirmed]

    def by_status(self, status: FindingStatus) -> list[Finding]:
        return [f for f in self.findings if f.status == status]
