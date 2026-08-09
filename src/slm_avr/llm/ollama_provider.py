"""Ollama-backed LLM provider.

Speaks the local Ollama HTTP API (http://localhost:11434 by default). Works
identically whether the target model is a fully on-premise SLM pulled with
`ollama pull qwen2.5-coder:7b` or an Ollama Cloud-proxied model such as
`glm-5.2:cloud` -- the client only cares that the Ollama daemon answers
/api/chat.
"""

from __future__ import annotations

import requests

from slm_avr.llm.base import LLMError, LLMProvider


class OllamaProvider(LLMProvider):
    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:3b",
        temperature: float = 0.2,
        timeout: int = 180,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.host}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            raise LLMError(
                f"could not reach Ollama at {self.host}. "
                "Is `ollama serve` running?"
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMError(
                f"Ollama request timed out after {self.timeout}s "
                f"(model={self.model})"
            ) from e

        if resp.status_code == 404:
            raise LLMError(
                f"model '{self.model}' not found on Ollama host {self.host}. "
                f"Pull it first: `ollama pull {self.model}`."
            )
        if resp.status_code != 200:
            raise LLMError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        message = data.get("message", {})
        content = message.get("content", "")
        if not content:
            raise LLMError(f"Ollama returned an empty completion: {data}")
        return content
