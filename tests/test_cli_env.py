"""Tests for local .env loading."""

from __future__ import annotations

from protocol_siftpp.cli import _load_dotenv


def test_load_dotenv_sets_missing_values(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=fake-key\nIGNORED\n", encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    _load_dotenv(env_file)

    assert __import__("os").environ["DEEPSEEK_API_KEY"] == "fake-key"


def test_load_dotenv_does_not_override_existing_values(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=file-key\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "existing-key")

    _load_dotenv(env_file)

    assert __import__("os").environ["DEEPSEEK_API_KEY"] == "existing-key"
