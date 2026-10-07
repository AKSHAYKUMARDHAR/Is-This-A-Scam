"""Optional link reputation check with the Google Safe Browsing Lookup API (v4).

On when SAFE_BROWSING_API_KEY is set. A link on Google's list of phishing, malware or unwanted
software sites becomes a hard rule flag ("known_bad_link"), so the verdict is "Likely scam" whatever
the model says. Only the links are sent, never the message. Any error, timeout or missing key means
"no information": the check never blocks or slows a verdict by more than its timeout.

The Lookup API is free for non-commercial use; a commercial service would use Google's Web Risk API.
"""
import time

import httpx

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


class SafeBrowsing:
    def __init__(self, api_key: str, timeout: float = 2.5, ttl: float = 3600, transport: httpx.AsyncBaseTransport | None = None):
        self.api_key, self.timeout, self.ttl, self.transport = api_key, timeout, ttl, transport
        self.cache: dict[str, tuple[float, bool]] = {}
        self.errors = 0

    @staticmethod
    def _full(url: str) -> str:
        return url if url.lower().startswith(("http://", "https://")) else "http://" + url

    async def bad_links(self, links: list[str]) -> list[str]:
        """The subset of links Google lists as unsafe; [] on any error."""
        now = time.time()
        wanted = list(dict.fromkeys(self._full(u) for u in links))[:20]
        unknown = [u for u in wanted if u not in self.cache or now - self.cache[u][0] > self.ttl]
        if unknown:
            body = {
                "client": {"clientId": "is-this-a-scam", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"],
                               "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in unknown]},
            }
            try:
                async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                    r = await client.post(ENDPOINT, params={"key": self.api_key}, json=body)
                r.raise_for_status()
                listed = {m.get("threat", {}).get("url") for m in r.json().get("matches", [])}
            except (httpx.HTTPError, ValueError):
                self.errors += 1
                return [u for u in wanted if self.cache.get(u, (0, False))[1]]
            for u in unknown:
                self.cache[u] = (now, u in listed)
            if len(self.cache) > 5000:
                self.cache.clear()
        return [u for u in wanted if self.cache[u][1]]
