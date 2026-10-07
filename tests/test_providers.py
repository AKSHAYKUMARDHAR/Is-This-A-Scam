"""Provider adapters with mocked SDK clients (no network, no keys)."""
import asyncio
import json
from types import SimpleNamespace as NS

import pytest

from checker.llm import ClaudeProvider, LLMError
from checker.prompts import SCHEMA

ANSWER = {"label": "scam", "confidence": 0.9, "scam_type": "bank_kyc", "red_flags": [], "genuine_signs": [], "summary": "x"}


class FakeMessages:
    def __init__(self, response):
        self.response, self.kwargs = response, None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def claude_with(response):
    messages = FakeMessages(response)
    client = NS(beta=NS(messages=messages))
    return ClaudeProvider(model="claude-opus-5-5", client=client), messages


def response(stop_reason="end_turn", text=json.dumps(ANSWER)):
    return NS(stop_reason=stop_reason, content=[NS(type="thinking", thinking=""), NS(type="text", text=text)],
              usage=NS(input_tokens=900, output_tokens=120))


def test_claude_request_shape_and_parsing():
    provider, messages = claude_with(response())
    out, usage = asyncio.run(provider.classify("Output language: English\n<content>\nhi\n</content>"))
    assert out["label"] == "scam" and usage == {"input_tokens": 900, "output_tokens": 120}
    kw = messages.kwargs
    assert kw["model"] == "claude-opus-5-5"
    assert kw["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert kw["output_config"]["effort"] == "low"
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert "thinking" not in kw and "temperature" not in kw        # not accepted on Claude Opus 5.5
    assert kw["messages"][0]["role"] == "user" and kw["system"]


def test_claude_refusal_and_truncation_raise():
    for stop in ("refusal", "max_tokens"):
        provider, _ = claude_with(response(stop_reason=stop))
        with pytest.raises(LLMError):
            asyncio.run(provider.classify("x"))


def test_claude_invalid_json_raises():
    provider, _ = claude_with(response(text="not json"))
    with pytest.raises(LLMError):
        asyncio.run(provider.classify("x"))


def test_claude_image_transcription_request():
    provider, messages = claude_with(response(text=json.dumps({"text": "Payment successful", "screen_kind": "payment_confirmation"})))
    out, _ = asyncio.run(provider.transcribe(b"\x89PNG", "image/png"))
    assert out["screen_kind"] == "payment_confirmation"
    block = messages.kwargs["messages"][0]["content"][0]
    assert block["type"] == "image" and block["source"]["media_type"] == "image/png"
    assert "system" not in messages.kwargs
