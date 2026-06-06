"""Model/provider + loop configuration for the agents."""

from __future__ import annotations

import os
from typing import Literal

Provider = Literal["anthropic", "deepseek"]

DEFAULT_PROVIDER: Provider = "anthropic"

# Opus 4.8: most capable when Anthropic credentials are available.
ANTHROPIC_MODEL = "claude-opus-4-8"

# DeepSeek's current official model name for higher-accuracy API runs.
DEEPSEEK_MODEL = "deepseek-v4-pro"
DEEPSEEK_ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"

MAX_TOKENS = 16_000
ANTHROPIC_MESSAGE_OPTIONS = {
    "thinking": {"type": "adaptive"},
    "output_config": {"effort": "high"},
}

# Safety rails so a run can't loop forever / blow up cost.
MAX_TURNS_PER_AGENT = 24      # model<->tool round trips within one agent activation
MAX_TOOL_RESULT_CHARS = 40_000  # cap tool output handed back to the model
DEFAULT_MAX_ITERATIONS = 3   # investigator <-> skeptic self-correction rounds


def normalize_provider(value: str | None) -> Provider:
    provider = (value or os.environ.get("SIFTPP_LLM_PROVIDER") or DEFAULT_PROVIDER).lower()
    if provider not in ("anthropic", "deepseek"):
        raise ValueError("provider must be 'anthropic' or 'deepseek'")
    return provider  # type: ignore[return-value]


def default_model(provider: Provider) -> str:
    override = os.environ.get("SIFTPP_MODEL")
    if override:
        return override
    if provider == "deepseek":
        return DEEPSEEK_MODEL
    return ANTHROPIC_MODEL


def message_options(provider: Provider) -> dict:
    """Provider-specific kwargs for `client.messages.create`.

    DeepSeek's Anthropic-compatible endpoint accepts the Messages shape, but we
    keep provider-specific Anthropic beta knobs off the DeepSeek path.
    """
    if provider == "anthropic":
        return dict(ANTHROPIC_MESSAGE_OPTIONS)
    return {}
