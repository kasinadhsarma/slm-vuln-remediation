"""Pipeline configuration, loaded from config.yaml with sensible defaults."""

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
class Config:
    semgrep_config_paths: list[str] = field(
        default_factory=lambda: [str(DEFAULT_RULES_PATH)]
    )
    exemplars_path: str = str(DEFAULT_EXEMPLARS_PATH)
    max_iterations: int = 3
    top_k_exemplars: int = 3
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    llm_provider: str = "ollama"  # "ollama" | "mock"

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        candidate = Path(path) if path else PROJECT_ROOT / "config.yaml"
        if not candidate.exists():
            return cls()

        with open(candidate) as f:
            raw = yaml.safe_load(f) or {}

        ollama_raw = raw.get("ollama", {})
        ollama = OllamaConfig(
            host=ollama_raw.get(
                "host", os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            ),
            model=ollama_raw.get("model", "glm-5.2:cloud"),
            temperature=ollama_raw.get("temperature", 0.2),
            timeout=ollama_raw.get("timeout", 180),
        )

        return cls(
            semgrep_config_paths=raw.get(
                "semgrep_config_paths", [str(DEFAULT_RULES_PATH)]
            ),
            exemplars_path=raw.get("exemplars_path", str(DEFAULT_EXEMPLARS_PATH)),
            max_iterations=raw.get("max_iterations", 3),
            top_k_exemplars=raw.get("top_k_exemplars", 3),
            ollama=ollama,
            llm_provider=raw.get("llm_provider", "ollama"),
        )
