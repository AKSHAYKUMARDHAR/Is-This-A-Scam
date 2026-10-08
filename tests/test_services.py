"""Optional services: Google Safe Browsing link check and the Postgres event log. No network needed."""
import asyncio
import json

import httpx

from api.store import EventStore, PostgresEventStore, make_store
from checker.linkcheck import SafeBrowsing
from checker.llm import FakeProvider
from checker.pipeline import CheckInput, run_check

UNSURE = {"label": "unsure", "confidence": 0.6, "scam_type": "none", "red_flags": [], "genuine_signs": [], "summary": "Not sure."}


def checker_for(listed: set[str], seen: list | None = None, status: int = 200) -> SafeBrowsing:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if seen is not None:
            seen.append((request.url.params.get("key"), body))
        urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
        return httpx.Response(status, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}}
                                                        for u in urls if u in listed]})
    return SafeBrowsing("test-key", transport=httpx.MockTransport(handler))


def test_safe_browsing_request_and_cache():
    seen = []
    sb = checker_for({"http://sbi-kyc-update.top/login"}, seen)
    bad = asyncio.run(sb.bad_links(["sbi-kyc-update.top/login", "https://www.amazon.in/orders"]))
    assert bad == ["http://sbi-kyc-update.top/login"]
    key, body = seen[0]
    assert key == "test-key" and body["threatInfo"]["threatEntryTypes"] == ["URL"]
    assert "SOCIAL_ENGINEERING" in body["threatInfo"]["threatTypes"]
    asyncio.run(sb.bad_links(["sbi-kyc-update.top/login"]))
    assert len(seen) == 1          # answered from the cache


def test_safe_browsing_fails_open():
    sb = checker_for({"http://x.top"}, status=500)
    assert asyncio.run(sb.bad_links(["x.top"])) == [] and sb.errors == 1


def test_listed_link_is_a_hard_flag():
    text = "Your parcel is waiting. Track it here: parcel-status-now.in/track"
    sb = checker_for({"http://parcel-status-now.in/track"})
    card, _ = asyncio.run(run_check(CheckInput(text=text), FakeProvider([UNSURE]), link_checker=sb))
    assert card["verdict"] == "scam" and "known_bad_link" in card["hard_flags"]
    assert any("Google" in f["why"] for f in card["red_flags"])
    card, _ = asyncio.run(run_check(CheckInput(text=text), FakeProvider([UNSURE]), link_checker=checker_for(set())))
    assert card["verdict"] == "unsure"


def test_event_store_choice_and_database_fallback(tmp_path):
    assert type(make_store("", str(tmp_path / "a.jsonl"))) is EventStore
    store = make_store("postgresql://user:pw@127.0.0.1:1/none?connect_timeout=1", str(tmp_path / "b.jsonl"))
    assert isinstance(store, PostgresEventStore)
    store.append({"type": "check", "verdict": "scam", "check_id": "c1"})     # database unreachable: goes to the file
    assert [e["check_id"] for e in store.events()] == ["c1"]
    assert store.stats()["overall"]["checks"] == 1


def test_keep_awake_pings_own_healthz():
    from api.main import keep_awake

    hits = []

    def handler(request):
        hits.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    async def run():
        task = asyncio.create_task(keep_awake("https://example.onrender.com", 0.01, httpx.MockTransport(handler)))
        await asyncio.sleep(0.1)
        task.cancel()

    asyncio.run(run())
    assert len(hits) >= 2 and all(h == "https://example.onrender.com/healthz" for h in hits)


def test_keep_awake_setting(monkeypatch):
    import importlib

    import checker.config as cfg
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://x.onrender.com/")
    monkeypatch.setenv("KEEP_AWAKE", "auto")
    assert importlib.reload(cfg).KEEP_AWAKE_URL == "https://x.onrender.com"
    monkeypatch.setenv("KEEP_AWAKE", "off")
    assert importlib.reload(cfg).KEEP_AWAKE_URL == ""
    monkeypatch.delenv("RENDER_EXTERNAL_URL")
    monkeypatch.setenv("KEEP_AWAKE", "auto")
    assert importlib.reload(cfg).KEEP_AWAKE_URL == ""
