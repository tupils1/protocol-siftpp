"""Client-side tools (not MCP): the structured channels the agents use to emit
findings and reviews. Defined as Anthropic tool schemas so the model returns
well-typed objects we can record directly."""

from __future__ import annotations

SUBMIT_FINDING_TOOL = {
    "name": "submit_finding",
    "description": (
        "Record ONE evidence-backed conclusion. Call once per distinct finding. "
        "Only claim what the cited tool outputs actually show."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "claim": {
                "type": "string",
                "description": "The specific conclusion, e.g. 'PID 1640 reader_sl.exe "
                "shows injected code (Cridex)'.",
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
            "confidence": {"type": "number", "description": "0.0-1.0"},
            "mitre_attack": {
                "type": "array",
                "items": {"type": "string"},
                "description": "ATT&CK technique IDs, e.g. ['T1055'].",
            },
            "cited_tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Names of the read-only tools whose output supports this "
                "finding (e.g. ['vol_malfind', 'vol_pslist']).",
            },
            "rationale": {
                "type": "string",
                "description": "How the cited evidence supports the claim.",
            },
        },
        "required": ["claim", "severity", "confidence", "cited_tools", "rationale"],
    },
}

SUBMIT_REVIEW_TOOL = {
    "name": "submit_review",
    "description": "Record your adversarial verdict on the finding after trying to refute it.",
    "input_schema": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["confirmed", "inferred", "refuted"],
                "description": "confirmed=evidence directly supports; inferred=plausible "
                "but not directly shown; refuted=unsupported/contradicted.",
            },
            "confidence": {"type": "number", "description": "0.0-1.0"},
            "refutation_attempt": {
                "type": "string",
                "description": "What you checked in trying to DISPROVE the claim.",
            },
            "rationale": {"type": "string", "description": "Why this verdict/confidence."},
        },
        "required": ["status", "confidence", "refutation_attempt", "rationale"],
    },
}
