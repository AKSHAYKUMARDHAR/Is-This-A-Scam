"""Language detection for Hindi, Bengali and English, including Hindi and Bengali typed in Latin script.

Script decides first (Devanagari -> Hindi, Bengali script -> Bengali). Latin text is scored against
short lists of common romanised Hindi and Bengali words; English is the fallback.
"""
import re

from .text_utils import BENGALI, DEVANAGARI

_HI_LATN = {
    "hai", "hain", "aap", "aapka", "aapke", "aapki", "kya", "nahi", "nahin", "karo", "kare", "karein", "kijiye",
    "paise", "rupaye", "abhi", "turant", "hoga", "gaya", "gayi", "mera", "meri", "mere", "tum", "tumhara", "bhai",
    "beta", "aaj", "jaldi", "bhejo", "bhej", "batao", "batayein", "wala", "wali", "liye", "mein", "kal", "ho",
    "raha", "rahi", "hoon", "mat", "kar", "diya", "diye", "lena", "dena", "bol", "yeh", "ye", "woh", "kuch",
    "sirf", "milega", "milenge", "lagao", "kamao", "chahiye", "dunga", "baje", "pe", "par", "se", "ko",
    "tak", "jaunga", "jayega", "jayegi", "bhaiya", "rakhna", "khula", "karna", "karke", "hum", "mujhe", "tujhe",
    "tumhe", "accha", "acha", "theek", "thik", "bas", "kyun", "kaise", "kahan", "yahan", "wahan", "aaya", "aayi",
    "lekin", "aur", "haan", "bhi", "tha", "thi", "lijiye", "dijiye", "bataiye", "kijiye", "hoga", "dekh", "pahunch",
}
_BN_LATN = {
    "ami", "tumi", "apni", "apnar", "amar", "tomar", "korun", "koro", "kore", "korte", "hobe", "hoye", "achhe",
    "ache", "taka", "ekhuni", "ekhon", "kichu", "keno", "bolun", "pathan", "pathao", "dada", "didi", "bhalo",
    "theke", "jonno", "shathe", "sathe", "debo", "dibo", "paben", "kemon", "holo", "geche", "gechi", "bolchi",
    "thakun", "din", "nite", "pete", "eta", "ota", "ei", "oi", "kal", "aaj", "ajke", "ajkei", "porechi",
    "bari", "barite", "jabo", "ashbe", "ashben", "hoyeche", "hoyechen", "korechi", "mash", "chhar", "lagbe",
    "tor", "tui", "jabe", "korbe", "parle", "eso", "ashbo", "kheye", "boshe", "achi", "kache", "firiye", "bolbo",
    "bolche", "bolchhe", "dekho", "janash", "kinte", "chole", "sondhebela", "jachhi", "pouchhe", "kheyecho",
}
_WORD_RE = re.compile(r"[a-z]+")


def detect(text: str) -> str:
    """One of 'hi', 'bn', 'en', 'hi-Latn', 'bn-Latn'."""
    text = text or ""
    dev = len(re.findall(f"[{DEVANAGARI}]", text))
    ben = len(re.findall(f"[{BENGALI}]", text))
    latin = len(re.findall(r"[A-Za-z]", text))
    if dev or ben:
        if max(dev, ben) >= 0.25 * (dev + ben + latin):
            return "hi" if dev >= ben else "bn"
    words = _WORD_RE.findall(text.lower())
    hi = sum(w in _HI_LATN for w in words)
    bn = sum(w in _BN_LATN for w in words)
    # Short shared words ("kal", "aaj") count for both; require a margin and at least 2 hits.
    if hi >= 2 and hi > bn:
        return "hi-Latn"
    if bn >= 2 and bn > hi:
        return "bn-Latn"
    return "en"


def base(lang: str) -> str:
    """Output language for a detected language: 'hi', 'bn' or 'en'."""
    return (lang or "en").split("-")[0]
