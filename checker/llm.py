"""Model providers behind one small interface: classify(user_message) and transcribe(image).

- ClaudeProvider: Anthropic SDK, structured JSON output (output_config.format), adaptive thinking at
  low effort, and the server-side refusal fallback ("fallbacks": "default") so a safety decline on
  the primary model is retried on a fallback model inside the same call.
- GeminiProvider: google-genai on the free tier, JSON output constrained by response_json_schema,
  throttled to GEMINI_RPM with retries; a per-day quota error fails fast (QuotaExhausted).
- FakeProvider: scripted responses for tests.

Every call returns (parsed_json, usage) where usage is {"input_tokens", "output_tokens"}.
"""
import asyncio
import json
import os
import time

from . import config
from .prompts import SCHEMA, SYSTEM, TRANSCRIBE_PROMPT, TRANSCRIBE_SCHEMA

MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "5"))


class LLMError(Exception):
    """The provider call failed or was declined; the pipeline falls back to "Can't tell"."""


class QuotaExhausted(LLMError):
    """A per-day quota is used up; retrying today will not help."""


def _parse(text: str | None) -> dict:
    if not text:
        raise LLMError("empty response")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMError(f"invalid JSON: {text[:120]}") from e


class _RateLimiter:
    def __init__(self, rpm: float):
        self.interval, self.next_at, self.lock = 60.0 / max(rpm, 0.1), 0.0, asyncio.Lock()

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            delay = self.next_at - now
            self.next_at = max(now, self.next_at) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


class Provider:
    name = "none"
    model = "none"

    async def classify(self, user: str) -> tuple[dict, dict]:
        raise NotImplementedError

    async def transcribe(self, image: bytes, mime: str) -> tuple[dict, dict]:
        raise NotImplementedError


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(self, model: str | None = None, client=None):
        from google import genai

        self.model = model or config.GEMINI_MODEL
        self._client = client or genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        self._limiter = _RateLimiter(config.GEMINI_RPM)

    async def _generate(self, contents, system: str | None, schema: dict, max_tokens: int) -> tuple[dict, dict]:
        from google.genai import errors, types

        cfg = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_json_schema=schema,
            max_output_tokens=max_tokens,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        delay = 5.0
        for attempt in range(MAX_RETRIES + 1):
            await self._limiter.wait()
            try:
                resp = await self._client.aio.models.generate_content(model=self.model, contents=contents, config=cfg)
                um = resp.usage_metadata
                usage = {
                    "input_tokens": getattr(um, "prompt_token_count", 0) or 0,
                    "output_tokens": (getattr(um, "candidates_token_count", 0) or 0) + (getattr(um, "thoughts_token_count", 0) or 0),
                }
                return _parse(resp.text), usage
            except errors.APIError as e:
                details = (getattr(e, "details", None) or {}).get("error", {}).get("details", [])
                if any("PerDay" in v.get("quotaId", "") for d in details for v in d.get("violations", [])):
                    raise QuotaExhausted(f"Gemini daily quota exhausted for {self.model}") from e
                if getattr(e, "code", None) not in (429, 500, 502, 503, 504) or attempt == MAX_RETRIES:
                    raise LLMError(f"Gemini {getattr(e, 'code', '?')}: {str(e)[:200]}") from e
            except LLMError:
                raise
            except Exception as e:  # dropped connection, timeout, DNS
                if attempt == MAX_RETRIES:
                    raise LLMError(f"Gemini transport error: {type(e).__name__}: {str(e)[:200]}") from e
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)
        raise LLMError("unreachable")

    async def classify(self, user: str) -> tuple[dict, dict]:
        return await self._generate(user, SYSTEM, SCHEMA, 1500)

    async def transcribe(self, image: bytes, mime: str) -> tuple[dict, dict]:
        from google.genai import types

        contents = [types.Part.from_bytes(data=image, mime_type=mime), TRANSCRIBE_PROMPT]
        return await self._generate(contents, None, TRANSCRIBE_SCHEMA, 2000)


class ClaudeProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str | None = None, client=None):
        import anthropic

        self.model = model or config.CLAUDE_MODEL
        self._client = client or anthropic.AsyncAnthropic()

    async def _create(self, system: str | None, content, schema: dict) -> tuple[dict, dict]:
        import anthropic

        kwargs = {"system": system} if system else {}
        try:
            resp = await self._client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                messages=[{"role": "user", "content": content}],
                output_config={"effort": config.CLAUDE_EFFORT, "format": {"type": "json_schema", "schema": schema}},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                **kwargs,
            )
        except anthropic.RateLimitError as e:
            raise LLMError("Claude rate limited") from e
        except anthropic.APIStatusError as e:
            raise LLMError(f"Claude {e.status_code}: {e.message[:200]}") from e
        except anthropic.APIConnectionError as e:
            raise LLMError("Claude connection error") from e
        if resp.stop_reason == "refusal":
            raise LLMError("Claude declined the request")
        if resp.stop_reason == "max_tokens":
            raise LLMError("Claude hit max_tokens")
        text = next((b.text for b in resp.content if b.type == "text"), None)
        usage = {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}
        return _parse(text), usage

    async def classify(self, user: str) -> tuple[dict, dict]:
        return await self._create(SYSTEM, user, SCHEMA)

    async def transcribe(self, image: bytes, mime: str) -> tuple[dict, dict]:
        import base64

        content = [
            {"type": "image", "source": {"type": "base64", "media_type": mime, "data": base64.standard_b64encode(image).decode()}},
            {"type": "text", "text": TRANSCRIBE_PROMPT},
        ]
        return await self._create(None, content, TRANSCRIBE_SCHEMA)


class FakeProvider(Provider):
    """Returns scripted classifications in order (cycling), for tests and offline demos."""

    name = "fake"
    model = "fake"

    def __init__(self, responses: list[dict] | None = None, transcript: dict | None = None):
        self.responses = responses or [{"label": "unsure", "confidence": 0.5, "scam_type": "none", "red_flags": [], "genuine_signs": [], "summary": ""}]
        self.transcript = transcript or {"text": "", "screen_kind": "other"}
        self.calls = 0

    async def classify(self, user: str) -> tuple[dict, dict]:
        out = self.responses[self.calls % len(self.responses)]
        self.calls += 1
        if isinstance(out, Exception):
            raise out
        return dict(out), {"input_tokens": 0, "output_tokens": 0}

    async def transcribe(self, image: bytes, mime: str) -> tuple[dict, dict]:
        return dict(self.transcript), {"input_tokens": 0, "output_tokens": 0}


def get_provider() -> Provider | None:
    """The configured provider, or None when no credentials are set (rules-only mode)."""
    choice = config.LLM_PROVIDER
    has_claude = bool(os.getenv("ANTHROPIC_API_KEY"))
    has_gemini = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
    if choice == "anthropic" or (choice == "auto" and has_claude):
        return ClaudeProvider()
    if choice == "gemini" or (choice == "auto" and has_gemini):
        return GeminiProvider()
    return None
