"""Generic provider for any OpenAI chat-completions-compatible endpoint.

Together.ai, Fireworks.ai, Groq, OpenRouter, a self-hosted vLLM server --
anything speaking `POST {base_url}/chat/completions` with a Bearer token
works here. This is the production alternative to running Ollama yourself:
no local model, no persistent server for the model, just an API call, which
makes the backend deployable to any regular host (including short-lived
containers) instead of requiring a machine with the model loaded in memory.
"""

from __future__ import annotations

import requests

from slm_avr.llm.base import LLMError, LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float = 0.2,
        timeout: int = 120,
    ):
        if not api_key:
            raise LLMError(
                "OpenAICompatibleProvider requires an API key. Set "
                "OPENAI_COMPATIBLE_API_KEY (or config.yaml's "
                "openai_compatible.api_key)."
            )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "stream": False,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            resp = requests.post(
                url, json=payload, headers=headers, timeout=self.timeout
            )
        except requests.exceptions.ConnectionError as e:
            raise LLMError(f"could not reach inference API at {self.base_url}") from e
        except requests.exceptions.Timeout as e:
            raise LLMError(
                f"inference API request timed out after {self.timeout}s "
                f"(model={self.model})"
            ) from e

        if resp.status_code == 401:
            raise LLMError("inference API rejected the request: invalid API key")
        if resp.status_code == 404:
            raise LLMError(
                f"model '{self.model}' not found at {self.base_url}. "
                "Check the model name for this provider."
            )
        if resp.status_code != 200:
            raise LLMError(
                f"inference API returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected response shape from inference API: {data}") from e

        if not content:
            raise LLMError(f"inference API returned an empty completion: {data}")
        return content
