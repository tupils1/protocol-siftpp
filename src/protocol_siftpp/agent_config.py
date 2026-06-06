"""Model + loop configuration for the agents (see claude-api guidance)."""

from __future__ import annotations

# Opus 4.8: most capable; accuracy is judging criterion #2. Adaptive thinking +
# high effort suit a multi-step, intelligence-sensitive DFIR investigation.
MODEL = "claude-opus-4-8"
MAX_TOKENS = 16_000
THINKING = {"type": "adaptive"}
OUTPUT_CONFIG = {"effort": "high"}

# Safety rails so a run can't loop forever / blow up cost.
MAX_TURNS_PER_AGENT = 24      # model<->tool round trips within one agent activation
MAX_TOOL_RESULT_CHARS = 40_000  # cap tool output handed back to the model
DEFAULT_MAX_ITERATIONS = 3   # investigator <-> skeptic self-correction rounds
