from unittest.mock import Mock, patch

import pytest

from slm_avr.llm.base import LLMError
from slm_avr.llm.openai_compatible_provider import OpenAICompatibleProvider


def test_requires_an_api_key():
    with pytest.raises(LLMError, match="requires an API key"):
        OpenAICompatibleProvider(base_url="https://api.together.xyz/v1", api_key="", model="m")


def test_generate_sends_openai_shaped_request_and_parses_response():
    provider = OpenAICompatibleProvider(
        base_url="https://api.together.xyz/v1",
        api_key="test-key",
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
    )

    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "choices": [{"message": {"content": "```python\ndef f():\n    pass\n```"}}]
    }

    with patch("slm_avr.llm.openai_compatible_provider.requests.post", return_value=fake_response) as mock_post:
        result = provider.generate("system prompt", "user prompt")

    assert "def f()" in result
    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.together.xyz/v1/chat/completions"
    assert kwargs["headers"]["Authorization"] == "Bearer test-key"
    assert kwargs["json"]["model"] == "Qwen/Qwen2.5-Coder-32B-Instruct"
    assert kwargs["json"]["messages"][0] == {"role": "system", "content": "system prompt"}
    assert kwargs["json"]["messages"][1] == {"role": "user", "content": "user prompt"}


def test_generate_raises_on_invalid_api_key():
    provider = OpenAICompatibleProvider(
        base_url="https://api.together.xyz/v1", api_key="bad-key", model="m"
    )
    fake_response = Mock()
    fake_response.status_code = 401

    with patch("slm_avr.llm.openai_compatible_provider.requests.post", return_value=fake_response):
        with pytest.raises(LLMError, match="invalid API key"):
            provider.generate("s", "u")


def test_generate_raises_on_unexpected_response_shape():
    provider = OpenAICompatibleProvider(
        base_url="https://api.together.xyz/v1", api_key="k", model="m"
    )
    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"unexpected": "shape"}

    with patch("slm_avr.llm.openai_compatible_provider.requests.post", return_value=fake_response):
        with pytest.raises(LLMError, match="unexpected response shape"):
            provider.generate("s", "u")
