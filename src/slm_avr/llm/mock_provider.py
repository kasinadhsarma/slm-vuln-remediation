"""Deterministic mock LLM provider for tests and offline pipeline demos.

Returns a caller-supplied canned response (or an identity echo) instead of
calling a real model, so the orchestrator/agent plumbing can be exercised in
CI without Ollama installed or a GPU available.
"""

from __future__ import annotations

from collections.abc import Callable

from slm_avr.llm.base import LLMProvider


class MockProvider(LLMProvider):
    def __init__(self, responder: Callable[[str, str], str] | None = None):
        self._responder = responder
        self.calls: list[tuple[str, str]] = []

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt, user_prompt))
        if self._responder is not None:
            return self._responder(system_prompt, user_prompt)
        return user_prompt
