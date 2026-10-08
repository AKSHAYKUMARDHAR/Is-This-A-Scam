"""FastAPI service: the checker API plus the static web app.

    uvicorn api.main:app --reload            # http://localhost:8000

POST /api/check      text, call answers or a screenshot -> verdict card
POST /api/feedback   helpful / not helpful / wrong verdict / stopped me / shared ...
GET  /api/config     languages, urgent steps, whether a model is configured
GET  /api/stats      the PRD's success metrics from the event log (optional STATS_TOKEN)
GET  /healthz

Privacy: message text and images are processed in memory and never written anywhere. The event log
holds verdicts, types, languages, latency and feedback only. With SAFE_BROWSING_API_KEY set, the links
in a message (never the message) are sent to Google Safe Browsing.
"""
import asyncio
import base64
import binascii
import hashlib
import json
import os
import pathlib
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from checker import advice, config
from checker.linkcheck import SafeBrowsing
from checker.llm import QuotaExhausted, get_provider
from checker.pipeline import CheckInput, run_check
from checker.prompts import PROMPT_VERSION
from checker.taxonomy import LANGS

from .guards import BurstDetector, LRUCache, RateLimiter
from .store import FEEDBACK_EVENTS, hash_id, make_store

WEB = pathlib.Path(__file__).resolve().parent.parent / "web"
CALL_FIELDS = {"claimed", "asked", "threat", "video_or_secret", "safe_account", "details"}

async def keep_awake(url: str, every_s: float, transport: httpx.AsyncBaseTransport | None = None) -> None:
    """Ping our own /healthz through the public URL, so the free host never sees 15 idle minutes.
    /healthz never calls the model, so this costs no quota."""
    async with httpx.AsyncClient(timeout=30, transport=transport) as client:
        while True:
            await asyncio.sleep(every_s)
            try:
                await client.get(f"{url}/healthz")
            except httpx.HTTPError:
                pass


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(keep_awake(config.KEEP_AWAKE_URL, 60 * config.KEEP_AWAKE_MINUTES)) if config.KEEP_AWAKE_URL else None
    yield
    if task:
        task.cancel()


app = FastAPI(title="Is This a Scam?", docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)
provider = get_provider()
store = make_store(config.DATABASE_URL, config.LOG_PATH)
link_checker = SafeBrowsing(config.SAFE_BROWSING_API_KEY) if config.SAFE_BROWSING_API_KEY else None
limiter = RateLimiter(config.RATE_LIMIT_PER_HOUR)
cache = LRUCache()
bursts = BurstDetector()


class CheckRequest(BaseModel):
    kind: str = Field("text", pattern="^(text|call|image)$")
    text: str = ""
    call: dict | None = None
    image_b64: str | None = None
    image_mime: str = Field("image/png", pattern="^image/(png|jpeg|webp)$")
    lang: str = "auto"
    client_id: str | None = Field(None, max_length=64)
    variant: str | None = Field(None, max_length=32)
    ref: str | None = Field(None, max_length=16)
    relang: bool = False          # same message re-checked only to switch language: not a new check in the metrics


class FeedbackRequest(BaseModel):
    check_id: str | None = Field(None, max_length=32)
    client_id: str | None = Field(None, max_length=64)
    event: str
    variant: str | None = Field(None, max_length=32)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


@app.post("/api/check")
async def check(req: CheckRequest, request: Request):
    ip = client_ip(request)
    if not limiter.allow(ip):
        raise HTTPException(429, "Too many checks from this connection. Please try again in a while.")

    image = None
    if req.kind == "text":
        if not req.text.strip():
            raise HTTPException(422, "Paste a message to check.")
        if len(req.text) > config.MAX_TEXT_CHARS:
            raise HTTPException(413, f"Please paste at most {config.MAX_TEXT_CHARS} characters.")
        content_key = req.text.strip()
    elif req.kind == "call":
        call = {k: v for k, v in (req.call or {}).items() if k in CALL_FIELDS}
        if not call:
            raise HTTPException(422, "Answer at least one question about the call.")
        if len(str(call.get("details", ""))) > config.MAX_TEXT_CHARS:
            raise HTTPException(413, f"Please keep the description under {config.MAX_TEXT_CHARS} characters.")
        req.call = call
        content_key = json.dumps(call, sort_keys=True, ensure_ascii=False)
    else:
        if not req.image_b64:
            raise HTTPException(422, "Upload a screenshot to check.")
        try:
            image = base64.b64decode(req.image_b64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "The screenshot could not be read.")
        if len(image) > config.MAX_IMAGE_BYTES:
            raise HTTPException(413, "Please upload a screenshot under 4 MB.")
        content_key = hashlib.sha256(image).hexdigest()

    lang = req.lang if req.lang in LANGS else "auto"
    message_hash = hashlib.sha256(f"{req.kind}|{content_key}".encode()).hexdigest()
    cache_key = f"{message_hash}|{lang}|{PROMPT_VERSION}"
    burst = bursts.observe(message_hash, ip)

    card = cache.get(cache_key)
    cached = card is not None
    if not cached:
        inp = CheckInput(kind=req.kind, text=req.text, call=req.call, image=image, image_mime=req.image_mime, ui_lang=lang)
        try:
            card, trace = await run_check(inp, provider, link_checker=link_checker)
        except QuotaExhausted:
            raise HTTPException(503, "The checker is at its daily limit. Please try again tomorrow, or call 1930 if you need help now.")
        cache.put(cache_key, card)
        model_calls, errors = trace.calls, len(trace.errors)
    else:
        card = {**card, "check_id": uuid.uuid4().hex[:12], "latency_ms": 0}   # feedback stays per check
        model_calls, errors = 0, 0

    await asyncio.to_thread(store.append, {
        "type": "check", "check_id": card["check_id"], "client": hash_id(req.client_id), "variant": req.variant, "ref": req.ref,
        "kind": req.kind, "lang": card["lang"], "detected_lang": card["detected_lang"], "verdict": card["verdict"],
        "scam_type": card["scam_type"], "reason": card["reason"], "hard_flags": card["hard_flags"],
        "latency_ms": card["latency_ms"] if not cached else 0, "cached": cached, "model_calls": model_calls,
        "model_errors": errors, "burst": burst, "relang": req.relang,
        "provider": getattr(provider, "name", None), "model": getattr(provider, "model", None),
    })
    public = {k: v for k, v in card.items() if k not in ("hard_flags", "reason")}
    return JSONResponse(public)


@app.post("/api/feedback")
async def feedback(req: FeedbackRequest):
    if req.event not in FEEDBACK_EVENTS:
        raise HTTPException(422, "Unknown event.")
    await asyncio.to_thread(store.append, {"type": "feedback", "check_id": req.check_id, "client": hash_id(req.client_id),
                                           "event": req.event, "variant": req.variant})
    return {"ok": True}


@app.get("/api/config")
async def get_config():
    return {
        "languages": LANGS,
        "model_available": provider is not None,
        "urgent_steps": advice.URGENT_STEPS,
        "max_text_chars": config.MAX_TEXT_CHARS,
    }


@app.get("/api/stats")
async def stats(x_stats_token: str | None = Header(None)):
    token = os.getenv("STATS_TOKEN")
    if token and x_stats_token != token:
        raise HTTPException(401, "Stats need a token.")
    return await asyncio.to_thread(store.stats)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "model": getattr(provider, "model", None), "commit": os.getenv("RENDER_GIT_COMMIT", "")[:7] or None,
            "event_store": "postgres" if config.DATABASE_URL else "file", "safe_browsing": link_checker is not None,
            "keep_awake": bool(config.KEEP_AWAKE_URL)}


@app.get("/")
async def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="web")
