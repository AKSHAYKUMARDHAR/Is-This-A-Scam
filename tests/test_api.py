"""API: checks, feedback, stats, limits and privacy of the event log."""
import base64
import importlib
import json

import pytest
from fastapi.testclient import TestClient

from checker.llm import FakeProvider

SCAM = {"label": "scam", "confidence": 0.95, "scam_type": "bank_kyc", "red_flags": [], "genuine_signs": [],
        "summary": "Looks like a fake bank message."}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "5")
    monkeypatch.delenv("STATS_TOKEN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    import checker.config
    importlib.reload(checker.config)
    import api.main
    main = importlib.reload(api.main)
    main.provider = FakeProvider([SCAM], transcript={"text": "Payment successful ₹1,200 to Sharma Store", "screen_kind": "payment_confirmation"})
    return TestClient(main.app), tmp_path / "events.jsonl"


def test_text_check_returns_a_card_and_logs_no_text(client):
    c, log = client
    text = "Dear customer, your KYC is pending, update it through the link we send you today."
    r = c.post("/api/check", json={"kind": "text", "text": text, "client_id": "abc", "variant": "verdict_first"})
    assert r.status_code == 200
    card = r.json()
    assert card["verdict"] == "scam" and card["next_steps"] and card["check_id"]
    assert "hard_flags" not in card and "reason" not in card
    logged = log.read_text(encoding="utf-8")
    assert "KYC is pending" not in logged and '"client": "abc"' not in logged
    assert json.loads(logged.splitlines()[0])["verdict"] == "scam"


def test_call_and_image_checks(client):
    c, _ = client
    r = c.post("/api/check", json={"kind": "call", "call": {"claimed": "bank_rbi", "asked": ["otp_pin"], "threat": "account_block"}})
    assert r.status_code == 200 and r.json()["verdict"] == "scam"
    img = base64.b64encode(b"\x89PNG fake bytes").decode()
    r = c.post("/api/check", json={"kind": "image", "image_b64": img, "image_mime": "image/png"})
    assert r.status_code == 200 and r.json()["verdict"] == "unsure"


def test_validation(client):
    c, _ = client
    assert c.post("/api/check", json={"kind": "text", "text": "   "}).status_code == 422
    assert c.post("/api/check", json={"kind": "text", "text": "x" * 2001}).status_code == 413
    assert c.post("/api/check", json={"kind": "call", "call": {}}).status_code == 422
    assert c.post("/api/check", json={"kind": "image", "image_b64": "not base64!!"}).status_code == 422
    assert c.post("/api/check", json={"kind": "video", "text": "hi"}).status_code == 422


def test_rate_limit(client):
    c, _ = client
    codes = [c.post("/api/check", json={"kind": "text", "text": f"Message number {i} about a parcel delivery today"}).status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]


def test_cache_hit_gets_a_new_check_id(client):
    c, _ = client
    body = {"kind": "text", "text": "Your HDFC account is blocked, verify at hdfc-verify.xyz now"}
    a, b = c.post("/api/check", json=body).json(), c.post("/api/check", json=body).json()
    assert a["verdict"] == b["verdict"] and a["check_id"] != b["check_id"]


def test_feedback_and_stats(client):
    c, _ = client
    card = c.post("/api/check", json={"kind": "text", "text": "Your SBI KYC expires today, update at sbi-kyc.xyz", "client_id": "u1", "variant": "verdict_first"}).json()
    assert c.post("/api/feedback", json={"event": "helpful", "check_id": card["check_id"], "client_id": "u1"}).json() == {"ok": True}
    assert c.post("/api/feedback", json={"event": "shared", "check_id": card["check_id"], "client_id": "u1"}).status_code == 200
    assert c.post("/api/feedback", json={"event": "hacked"}).status_code == 422
    s = c.get("/api/stats").json()
    assert s["overall"]["checks"] == 1 and s["overall"]["helpful_rate_pct"] == 100.0 and s["overall"]["share_rate_pct"] == 100.0
    assert "verdict_first" in s["by_variant"]


def test_config_and_static(client):
    c, _ = client
    cfg = c.get("/api/config").json()
    assert set(cfg["urgent_steps"]) == {"en", "hi", "bn"} and cfg["model_available"] is True
    assert c.get("/").status_code == 200 and "Is This a Scam?" in c.get("/").text
    assert c.get("/app.js").status_code == 200
