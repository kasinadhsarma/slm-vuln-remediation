"""Pipeline configuration, loaded from config.yaml with sensible defaults.

Every field can be overridden by an environment variable so the same
config.yaml works for local development (Ollama) and a production
deployment (a hosted OpenAI-compatible inference API) without maintaining
two files -- just set env vars on the host (Render, Railway, etc.).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES_PATH = PROJECT_ROOT / "rules" / "custom_rules.yaml"
DEFAULT_EXEMPLARS_PATH = (
    Path(__file__).resolve().parent / "retrieval" / "exemplars" / "cwe_fixes.json"
)


@dataclass
class OllamaConfig:
    host: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:3b"
    temperature: float = 0.2
    timeout: int = 180


@dataclass
class OpenAICompatibleConfig:
    """Any provider that speaks the OpenAI chat-completions wire format:
    Together.ai, Fireworks.ai, Groq, OpenRouter, vLLM, LM Studio, etc."""

    base_url: str = "https://api.together.xyz/v1"
    api_key: str = ""
    model: str = "Qwen/Qwen2.5-Coder-32B-Instruct"
    temperature: float = 0.2
    timeout: int = 120


@dataclass
class Config:
    semgrep_config_paths: list[str] = field(
        default_factory=lambda: [str(DEFAULT_RULES_PATH)]
    )
    exemplars_path: str = str(DEFAULT_EXEMPLARS_PATH)
    max_iterations: int = 3
    top_k_exemplars: int = 3
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    openai_compatible: OpenAICompatibleConfig = field(
        default_factory=OpenAICompatibleConfig
    )
    llm_provider: str = "ollama"  # "ollama" | "openai_compatible" | "mock"

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        candidate = Path(path) if path else PROJECT_ROOT / "config.yaml"
        raw = {}
        if candidate.exists():
            with open(candidate) as f:
                raw = yaml.safe_load(f) or {}

        ollama_raw = raw.get("ollama", {})
        ollama = OllamaConfig(
            host=os.environ.get("OLLAMA_HOST", ollama_raw.get("host", "http://localhost:11434")),
            model=os.environ.get("OLLAMA_MODEL", ollama_raw.get("model", "qwen2.5-coder:3b")),
            temperature=ollama_raw.get("temperature", 0.2),
            timeout=ollama_raw.get("timeout", 180),
        )

        oai_raw = raw.get("openai_compatible", {})
        openai_compatible = OpenAICompatibleConfig(
            base_url=os.environ.get(
                "OPENAI_COMPATIBLE_BASE_URL",
                oai_raw.get("base_url", "https://api.together.xyz/v1"),
            ),
            api_key=os.environ.get(
                "OPENAI_COMPATIBLE_API_KEY", oai_raw.get("api_key", "")
            ),
            model=os.environ.get(
                "OPENAI_COMPATIBLE_MODEL",
                oai_raw.get("model", "Qwen/Qwen2.5-Coder-32B-Instruct"),
            ),
            temperature=oai_raw.get("temperature", 0.2),
            timeout=oai_raw.get("timeout", 120),
        )

        return cls(
            semgrep_config_paths=raw.get(
                "semgrep_config_paths", [str(DEFAULT_RULES_PATH)]
            ),
            exemplars_path=raw.get("exemplars_path", str(DEFAULT_EXEMPLARS_PATH)),
            max_iterations=raw.get("max_iterations", 3),
            top_k_exemplars=raw.get("top_k_exemplars", 3),
            ollama=ollama,
            openai_compatible=openai_compatible,
            llm_provider=os.environ.get(
                "SLM_AVR_LLM_PROVIDER", raw.get("llm_provider", "ollama")
            ),
        )
