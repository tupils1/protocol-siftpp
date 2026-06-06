"""Tests for provider/model configuration."""

from __future__ import annotations

import pytest

from protocol_siftpp.agent_config import (
    ANTHROPIC_MODEL,
    DEEPSEEK_MODEL,
    default_model,
    message_options,
    normalize_provider,
)


def test_provider_defaults_and_models(monkeypatch):
    monkeypatch.delenv("SIFTPP_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SIFTPP_MODEL", raising=False)

    assert normalize_provider(None) == "anthropic"
    assert normalize_provider("deepseek") == "deepseek"
    assert default_model("anthropic") == ANTHROPIC_MODEL
    assert default_model("deepseek") == DEEPSEEK_MODEL


def test_model_override(monkeypatch):
    monkeypatch.setenv("SIFTPP_MODEL", "custom-model")
    assert default_model("deepseek") == "custom-model"


def test_provider_specific_message_options():
    assert "thinking" in message_options("anthropic")
    assert message_options("deepseek") == {}


def test_invalid_provider_rejected():
    with pytest.raises(ValueError):
        normalize_provider("other")
