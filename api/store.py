"""Event log and the metrics computed from it.

Each line is one event with no message text: a check (verdict, scam type, language, latency, variant)
or a feedback action (helpful, not helpful, wrong verdict, stopped me, shared, ...). Client IDs are
random per browser and are stored hashed. At this scale a JSONL file is enough; the metrics read it
in full.
"""
import hashlib
import json
import pathlib
import threading
import time
from collections import Counter, defaultdict

FEEDBACK_EVENTS = {"helpful", "not_helpful", "wrong_verdict", "stopped_me", "shared", "next_step_click",
                   "already_paid_open", "share_open"}


def hash_id(value: str | None) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest()[:16] if value else None


class EventStore:
    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def append(self, event: dict) -> None:
        event = {"ts": round(time.time(), 3), **event}
        with self.lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def stats(self) -> dict:
        """The PRD's success metrics, overall and per A/B variant."""
        events = self.events()
        checks = [e for e in events if e.get("type") == "check" and not e.get("relang")]
        feedback = [e for e in events if e.get("type") == "feedback"]
        by_check = defaultdict(set)
        for e in feedback:
            by_check[e.get("check_id")].add(e.get("event"))

        def summarise(subset: list[dict]) -> dict:
            n = len(subset)
            ids = {c["check_id"] for c in subset}
            fb = {i: by_check.get(i, set()) for i in ids}
            helpful = sum("helpful" in v for v in fb.values())
            rated = sum(bool(v & {"helpful", "not_helpful"}) for v in fb.values())
            users = {c.get("client") for c in subset if c.get("client")}
            per_user = Counter(c.get("client") for c in subset if c.get("client"))
            latencies = sorted(c.get("latency_ms", 0) for c in subset)
            verdicts = Counter(c.get("verdict") for c in subset)
            return {
                "checks": n,
                "unique_users": len(users),
                "returning_users_pct": round(100 * sum(1 for v in per_user.values() if v > 1) / len(users), 1) if users else None,
                "helpful_checks": helpful,
                "helpful_rate_pct": round(100 * helpful / rated, 1) if rated else None,
                "rated_checks": rated,
                "share_rate_pct": round(100 * sum("shared" in v for v in fb.values()) / n, 1) if n else None,
                "wrong_verdict_rate_pct": round(100 * sum("wrong_verdict" in v for v in fb.values()) / n, 1) if n else None,
                "stopped_me": sum("stopped_me" in v for v in fb.values()),
                "cant_tell_rate_pct": round(100 * verdicts.get("unsure", 0) / n, 1) if n else None,
                "verdicts": dict(verdicts),
                "p95_latency_ms": latencies[int(0.95 * (len(latencies) - 1))] if latencies else None,
            }

        week_ago = time.time() - 7 * 86400
        recent = [c for c in checks if c["ts"] >= week_ago]
        variants = sorted({c.get("variant") for c in checks if c.get("variant")})
        share_opens = sum(1 for e in feedback if e.get("event") == "share_open")
        return {
            "overall": summarise(checks),
            "last_7_days": summarise(recent),
            "by_variant": {v: summarise([c for c in checks if c.get("variant") == v]) for v in variants},
            "by_language": dict(Counter(c.get("lang") for c in checks)),
            "by_scam_type": dict(Counter(c.get("scam_type") for c in checks if c.get("scam_type"))),
            "share_conversion_pct": round(100 * sum(1 for c in checks if c.get("ref") == "share") / share_opens, 1) if share_opens else None,
            "duplicate_bursts": sum(1 for c in checks if c.get("burst")),
        }
