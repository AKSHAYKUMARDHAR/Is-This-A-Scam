"""Shared text helpers: URL, UPI ID and phone extraction, and script ranges.

Indian messages mix scripts, so word boundaries are handled explicitly: Python's \\b does not
treat Devanagari or Bengali vowel signs as word characters.
"""
import re
import unicodedata

DEVANAGARI = "ऀ-ॿ"
BENGALI = "ঀ-৿"
DIGITS = "0-9০-৯०-९"   # ASCII, Bengali and Devanagari digits

_TLDS = (
    "com|in|net|org|co|io|info|xyz|top|click|online|site|live|buzz|icu|shop|vip|help|app|me|ly|gl|it|"
    "to|gy|cc|biz|link|store|tech|pro|club|sbi|tk|ml|ga|cf|gq|rest|cyou|sbs|cfd|quest|monster|work|win|"
    "loan|bid|cn|ru"
)
# Host labels ending in a known TLD. A hyphen followed by a non-ASCII letter ends the URL, so
# "wbsedcl.in-এ" (Bengali case suffix) yields "wbsedcl.in". Emails and UPI IDs are excluded.
URL_RE = re.compile(
    r"(?<![@\w.])(?:https?://)?(?:www\.)?"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r"))"
    r"(?![a-z0-9]|-[a-z0-9]|\.[a-z0-9]|@)"
    r"(/[^\s<>\"'।]*)?",
    re.I,
)
UPI_RE = re.compile(r"(?<![\w.@])([a-z0-9][a-z0-9._-]{1,48})@([a-z][a-z0-9]{1,20})(?![\w.@])", re.I)
PHONE_RE = re.compile(r"(?<![\d\w])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")

OFFICIAL_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "sbi", "sbicard.com", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in", "ucobank.com",
    "bankofindia.co.in", "idfcfirstbank.com", "yesbank.in", "indusind.com", "rbi.org.in", "npci.org.in",
    "licindia.in", "irctc.co.in", "amazon.in", "amzn.in", "amzn.to", "flipkart.com", "fkrt.it", "myntra.com",
    "myntr.it", "paytm.com", "phonepe.com", "bluedart.com", "delhivery.com", "dtdc.in", "bescom.co.in",
    "wbsedcl.in", "cesc.co.in", "tatapower-ddl.com", "bsesdelhi.com", "jio.com", "airtel.in", "myvi.in",
    "zerodha.com", "groww.in", "upstox.com", "kmcgov.in", "swiggy.com", "zomato.com", "uber.com",
}
BRAND_TOKENS = (
    "sbi", "yono", "hdfc", "icici", "axis", "kotak", "pnb", "baroda", "canara", "paytm", "phonepe", "gpay",
    "googlepay", "amazon", "amzn", "flipkart", "myntra", "bluedart", "delhivery", "dtdc", "indiapost",
    "fedex", "uidai", "aadhaar", "aadhar", "incometax", "epfo", "parivahan", "echallan", "fastag", "npci",
    "rbi", "sebi", "lic", "irctc", "jio", "airtel", "bsnl", "indane", "bharatgas", "lpg", "bescom",
    "wbsedcl", "cesc", "zerodha", "groww", "infosys", "tcs", "wipro",
)
LURE_TOKENS = ("kyc", "refund", "reward", "verify", "update", "unlock", "secure", "login", "redeliver", "cashback")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
    "rebrand.ly", "goo.gl", "shorturl.com",
}
RISKY_TLDS = {
    "xyz", "top", "click", "online", "site", "live", "buzz", "icu", "vip", "info", "help", "rest", "cyou",
    "sbs", "cfd", "quest", "monster", "tk", "ml", "ga", "cf", "gq", "win", "loan", "bid",
}


def urls(text: str) -> list[tuple[str, str]]:
    """(host, full match) for each URL-like token, lower-cased host, trailing punctuation dropped."""
    out = []
    for m in URL_RE.finditer(text or ""):
        full = m.group(0).rstrip(".,;:!?)]}'\"")
        out.append((m.group(1).lower(), full))
    return out


def is_official(host: str) -> bool:
    host = host.lower().removeprefix("www.")
    if host.endswith(".gov.in") or host.endswith(".nic.in") or host == "gov.in":
        return True
    return any(host == d or host.endswith("." + d) for d in OFFICIAL_DOMAINS)


def upi_ids(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2).lower()) for m in UPI_RE.finditer(text or "")]


def indic_word(word: str, script: str) -> str:
    """Regex for a standalone word in an Indic script (no letters of that script on either side)."""
    return rf"(?<![{script}]){re.escape(word)}(?![{script}])"


def norm(s: str) -> str:
    """NFC with the Devanagari and Bengali nukta removed, so spelling variants compare equal."""
    return unicodedata.normalize("NFC", s or "").replace("़", "").replace("়", "")


def rx(pattern: str, flags: int = re.I | re.S) -> re.Pattern:
    """Compile a pattern after applying the same normalisation as the text it will search."""
    return re.compile(norm(pattern), flags)
