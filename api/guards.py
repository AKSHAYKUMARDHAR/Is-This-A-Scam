"""Abuse controls: a per-IP rate limit, a result cache, and near-duplicate burst detection.

Scammers may probe the checker to find wording that gets through (PRD, Safety). Rate limits slow
that down, and bursts of the same message from several IPs are flagged in the log for review.
"""
import time
from collections import OrderedDict, defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_s: float = 3600):
        self.limit, self.window = limit, window_s
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


class LRUCache:
    def __init__(self, size: int = 512):
        self.size, self.data = size, OrderedDict()

    def get(self, key):
        if key in self.data:
            self.data.move_to_end(key)
            return self.data[key]
        return None

    def put(self, key, value):
        self.data[key] = value
        self.data.move_to_end(key)
        while len(self.data) > self.size:
            self.data.popitem(last=False)


class BurstDetector:
    """True when the same message hash arrives from 3+ different IPs within 10 minutes."""

    def __init__(self, ips: int = 3, window_s: float = 600):
        self.ips, self.window = ips, window_s
        self.seen: dict[str, deque] = defaultdict(deque)

    def observe(self, message_hash: str, ip: str) -> bool:
        now = time.monotonic()
        q = self.seen[message_hash]
        while q and now - q[0][0] > self.window:
            q.popleft()
        q.append((now, ip))
        return len({i for _, i in q}) >= self.ips
