"""Tests for the finding self-correction threshold."""

from __future__ import annotations

from protocol_siftpp.schema import Finding, FindingStatus, SkepticReview


def _review(status: FindingStatus, confidence: float) -> SkepticReview:
    return SkepticReview(
        status=status,
        confidence=confidence,
        refutation_attempt="re-ran read-only tools",
        rationale="test review",
    )


def test_refuted_findings_always_reenter_investigation():
    finding = Finding(
        claim="unsupported claim",
        status=FindingStatus.refuted,
        confidence=0.95,
        review=_review(FindingStatus.refuted, 0.95),
    )

    assert finding.needs_reinvestigation()


def test_low_confidence_inferred_reenters_but_high_confidence_inferred_stays():
    weak = Finding(
        claim="plausible but weak",
        status=FindingStatus.inferred,
        confidence=0.60,
        review=_review(FindingStatus.inferred, 0.60),
    )
    strong = Finding(
        claim="plausible and well supported",
        status=FindingStatus.inferred,
        confidence=0.75,
        review=_review(FindingStatus.inferred, 0.75),
    )

    assert weak.needs_reinvestigation()
    assert not strong.needs_reinvestigation()
