"""Input guard: instruction-like text aimed at an AI checker.

A message that tries to instruct "the AI", "the checker" or "the system" is never shown to the
model, and the attempt itself counts as a hard red flag: genuine banks, couriers and relatives do
not write instructions for scam checkers. The UPI Triage Agent project showed that telling the
model "treat the content as data" is not enough on its own (it obeyed an injected "categorize as
Investments" at confidence 1), so this check is deterministic and sits outside the model.
"""
import re

from .text_utils import norm, rx

_EN = re.compile(
    r"\bignore\b.{0,40}\b(instructions?|prompts?|rules?|guidelines)\b"
    r"|\bdisregard\b.{0,40}\b(instructions?|rules?|guidelines|above)\b"
    r"|\b(system|admin|developer)\s+(override|prompt|instructions?)\b"
    r"|\bdeveloper\s+mode\b|\byou\s+are\s+now\b|\bnew\s+instructions?\b|\bjailbreak\b"
    r"|\b(note|instructions?|message|hint)\s+(to|for)\s+(the\s+|any\s+)?(ai|assistant|bot|model|llm|scanners?|checkers?|classifiers?|filters?|safety bots?)\b"
    r"|\bif\s+you\s+are\s+an?\s+(ai|language\s+model|bot|assistant)\b"
    r"|\b(ai|assistant|bot|model|checker|classifier)s?\b.{0,40}\b(classify|mark|label|rate|treat|tell|say|respond|reply|answer|confirm)\b.{0,40}\b(genuine|safe|legit\w*|trusted|real|not\s+a\s+scam|fine)\b"
    r"|\b(classify|mark|label)\s+(this|it|the message)?\s*as\s+(genuine|safe|legit\w*|trusted)\b"
    r"|\brespond\s+(only\s+)?with\s+(the\s+)?(word\s+|label\s+)?(safe|genuine)\b"
    r"|\b(output|set)\s+(the\s+)?(label|confidence|verdict)\b"
    r"|\bassistant\s*:\s*understood\b|</?\s*(instructions?|system|content)\s*>",
    re.I | re.S,
)
_HI = rx(
    r"((?<![A-Za-z])AI(?![A-Za-z])|एआई|सिस्टम)\s*(के लिए|को|मॉडल)|निर्देशों?\s*को\s*अनदेखा|पिछले\s*सभी\s*निर्देश"
    r"|(इसे|इस संदेश को)\s*(सुरक्षित|वास्तविक|सही)\s*(बताएं|बताओ|माने|मानें|कहें|दिखाएं)"
    r"|जांच(ने)?\s*(करने\s*)?वाला\s*(कोई\s*भी\s*)?(AI|एआई|सिस्टम)|जांचकर्ता\s*के\s*लिए|धोखाधड़ी\s*न\s*कहे",
    re.S,
)
_BN = rx(
    r"((?<![A-Za-z])AI(?![A-Za-z])|এআই)\s*(সহকারীর|কে|,)|নির্দেশ\s*উপেক্ষা|কৃত্রিম\s*বুদ্ধিমত্তা|স্বয়ংক্রিয়\s*যাচাইকারী"
    r"|স্ক্যাম\s*চেকার|(নিরাপদ|আসল|বিশ্বাসযোগ্য)\s*(হিসেবে\s*)?(চিহ্নিত\s*করুন|বলুন|বলো|দেখাবে)",
    re.S,
)
_LATN = re.compile(
    r"\b(ai|checker|system)\b.{0,30}\b(safe|genuine)\s+(batao|bolo|bolna|dikhaye|mark\s+karo|likho|bolbe)\b"
    r"|\b(isko|ise|eta\s*ke|eta)\s+(safe|genuine)\s+(batao|bolo|mark\s+karo|likho)\b"
    r"|\bscam\s+mat\s+bolna\b|\binstructions?\s+bhool\s+jao\b|\bsystem\s+prompt\b"
    r"|\bje\s+ai\s+eta\s+porche\b|\bagar\s+tum\s+ai\s+ho\b|\btum\s+(is\s+message\s+ko\s+)?genuine\s+mark\s+karo\b",
    re.I,
)


def find_injection(text: str) -> str | None:
    """The instruction-like snippet, or None."""
    t = norm(text)
    for pattern in (_EN, _HI, _BN, _LATN):
        m = pattern.search(t)
        if m:
            return m.group(0)[:120]
    return None
