"""Abstract LLM interface so the Patch Generator doesn't care which backend
(local Ollama SLM, cloud-proxied Ollama model, or a test mock) produces
the patch."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMError(RuntimeError):
    pass


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Return the raw model completion for the given prompt pair."""
        raise NotImplementedError
