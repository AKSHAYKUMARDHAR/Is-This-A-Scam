"""Mask personal numbers before any text leaves the server for the model API.

Masked: card numbers, 12-digit ID numbers (Aadhaar-like), long account numbers, mobile numbers,
OTP digits and PAN. Kept: amounts, links and UPI IDs, because the checker needs them to judge the
message (a personal UPI ID collecting a "fine" is a red flag; a merchant ID is not).
Links are protected first so their digits are never touched.
"""
import re

from .text_utils import DIGITS, PHONE_RE, URL_RE

D = f"[{DIGITS}]"
_CARD = re.compile(rf"(?<!{D})(?:{D}[ -]?){{12,18}}{D}(?!{D})")
_ID12 = re.compile(rf"(?<!{D}){D}{{4}}[ -]?{D}{{4}}[ -]?{D}{{4}}(?!{D})")
_LONG = re.compile(rf"(?<!{D}){D}{{9,18}}(?!{D})")
_OTP_AFTER = re.compile(
    rf"((?:OTP|one[\s-]?time password|code|PIN|ओटीपी|कोड|ওটিপি|কোড)[^{DIGITS}\n]{{0,25}}?)({D}{{4,8}})(?!{D})",
    re.I,
)
_OTP_BEFORE = re.compile(rf"(?<!{D})({D}{{4,8}})(?=\s+is\s+(?:your|the)\s+(?:OTP|one[\s-]?time))", re.I)
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")


def mask(text: str) -> tuple[str, dict]:
    """Return (masked text, counts per kind)."""
    text = text or ""
    protected: list[str] = []

    def _protect(m):
        protected.append(m.group(0))
        return f"\x00{len(protected) - 1}\x00"

    out = URL_RE.sub(_protect, text)
    counts: dict[str, int] = {}

    def _sub(pattern, label, s, repl=None):
        new, n = pattern.subn(repl or label, s)
        if n:
            counts[label] = counts.get(label, 0) + n
        return new

    out = _sub(_OTP_BEFORE, "[OTP]", out)
    out = _sub(_OTP_AFTER, "[OTP]", out, lambda m: m.group(1) + "[OTP]")
    out = _sub(_CARD, "[CARD-NUMBER]", out)
    out = _sub(_ID12, "[ID-NUMBER]", out)
    out = _sub(PHONE_RE, "[PHONE]", out)
    out = _sub(_LONG, "[ACCOUNT-NUMBER]", out)
    out = _sub(_PAN, "[PAN]", out)
    out = re.sub(r"\x00(\d+)\x00", lambda m: protected[int(m.group(1))], out)
    return out, counts
