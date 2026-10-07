"""Deterministic red-flag rules, run locally on the raw text before anything is sent to a model.

Three tiers:
- hard:   always "Likely scam", whatever the model says (PRD decision rule 1). Kept few and precise,
          because a hard flag skips the model's judgement entirely.
- strong: real warning signs that are not proof on their own. They never decide "Likely scam",
          but they block "No scam signs found" (the message falls back to "Can't tell").
- weak:   context for the explanation only.
Genuine signals (an official link, an awareness message) are reported for the explanation; they
never override a hard flag.

Separately, the rules list what the message asks the reader to do ("asks"). A message with no risky
ask (pay, open a link, call a number given in it, share a code or personal details, install an app,
scan a QR code, stay on a call) can't cost anyone anything yet, so the model alone can't call it a
scam (policy rule 8).

Every hard rule checks for negation or awareness wording around the match, so "never share your
OTP" and "there is no such thing as a digital arrest" do not fire. Indic text is normalised (NFC,
nukta removed) on both the pattern and the input side, so spelling variants of the same word match.
"""
import re
from dataclasses import dataclass, field

from .guard import find_injection
from .text_utils import (
    BENGALI, BRAND_TOKENS, DEVANAGARI, LURE_TOKENS, PHONE_RE, RISKY_TLDS, SHORTENERS, indic_word, is_official, norm, rx, upi_ids,
    urls,
)

HARD = ("injection", "asks_secret", "pin_to_receive", "remote_access", "apk_file", "digital_arrest",
        "safe_account", "official_fee_personal_upi", "guaranteed_returns", "task_scam", "power_cut_threat",
        "known_bad_link")   # known_bad_link: added by the pipeline from Google Safe Browsing, when it is on
STRONG = ("secrecy", "new_number_money", "upfront_fee", "personal_upi_payment", "prize_lottery",
          "lookalike_domain", "risky_link", "lure_link", "daily_earnings", "family_pressure", "official_asks_money",
          "return_request", "screenshot_claim", "withdrawal_fee")
RISKY_ASKS = ("pay", "link", "call_number", "share_secret", "share_details", "install_app", "scan_qr", "stay_on_call",
              "join_group")
# "contact" (call me, call back, press 1, reply on WhatsApp) is recorded but is not a risky ask: talking
# to someone costs nothing by itself, and the ask that follows can be checked again.


@dataclass
class Flag:
    code: str
    quote: str = ""


@dataclass
class RuleResult:
    hard: list[Flag] = field(default_factory=list)
    strong: list[Flag] = field(default_factory=list)
    weak: list[Flag] = field(default_factory=list)
    genuine: list[Flag] = field(default_factory=list)
    asks: list[Flag] = field(default_factory=list)
    type_hint: str | None = None
    type_fixed: bool = False    # True when a hard rule implies the type (e.g. guaranteed returns -> investment)

    def codes(self, tier: str) -> list[str]:
        return [f.code for f in getattr(self, tier)]

    def risky_ask(self) -> bool:
        return any(f.code in RISKY_ASKS for f in self.asks)


# ---- negation and awareness ---------------------------------------------------------------------
_NEG = [
    rx(r"\b(never|not|don'?t|dont|do\s+not|nobody|no\s+one|won'?t|avoid|beware|only\s+to\s+send)\b"),
    rx(r"\b(mat|nahi|nahin|na|kabhi|savdhan|kokhono|noy)\b"),
    rx("|".join([indic_word("न", DEVANAGARI), indic_word("मत", DEVANAGARI), indic_word("ना", DEVANAGARI),
                 "नहीं", "कभी", "सावधान"])),
    rx("|".join([indic_word("না", BENGALI), indic_word("নয", BENGALI), "কখনও", "কখনো", "সতর্ক", "বারণ", "নিষেধ"])),
]
_AWARE = rx(
    r"\b(beware|never|nobody|no\s+such\s+thing|nothing\s+called|is\s+a\s+(?:scam|fraud)|fraud\s+alert|stay\s+alert|"
    r"advisory|savdhan|kabhi\s+nahi|busted|racket|gang|accused)\b|cybercrime\.gov\.in|1930|सावधान|धोखा|कोई\s*चीज\s*नहीं|कभी|"
    r"नहीं\s*(?:करते|करती|होती)|गिरोह|ठग|সতর্ক|কখনও|করে\s*না|১৯৩০|চক্র|প্রতারক"
)
# Genuine products quote yearly rates ("7.25% p.a."); scams quote daily, weekly or monthly ones.
_YEARLY_PRODUCT = rx(r"\bp\.?\s?a\b\.?|per\s+annum|per\s+year|annual\w*|\bfd\b|fixed\s+deposit|\blic\b|insurance|policy|"
                     r"प्रति\s*वर्ष|सालाना|बीमा|পলিসি|বার্ষিক|বিমা")


def _negated(text: str, start: int, end: int, before: int = 45, after: int = 30) -> bool:
    window = text[max(0, start - before): end + after]
    return any(p.search(window) for p in _NEG)


def _first(patterns, text, neg=True, aware=False):
    """First match of any pattern that is not negated / not inside an awareness message."""
    if aware and _AWARE.search(text):
        return None
    for p in patterns:
        for m in p.finditer(text):
            if neg and _negated(text, m.start(), m.end()):
                continue
            return m
    return None


def _q(m) -> str:
    return re.sub(r"\s+", " ", m.group(0)).strip()[:80] if m else ""


# ---- hard rules ---------------------------------------------------------------------------------
_SECRET_EN = r"(?:otp|one[\s-]?time[\s-]?password|upi\s*pin|m-?pin|\bpin\b|cvv|password|verification\s+code|security\s+code)"
_ASK_EN = r"(?:share|send|tell|give|provide|forward|read\s+out|reply\s+with|say)"
_SECRET_LATN = r"(?:otp|pin|cvv|password|code)"
SECRET = [
    rx(rf"\b{_ASK_EN}\b\W+(?:[\w']+\W+){{0,4}}?{_SECRET_EN}"),
    rx(rf"{_SECRET_EN}\W+(?:[\w']+\W+){{0,5}}?(?:to|with)\s+(?:us|me|our|this)\b"),
    rx(r"(?:OTP|ओटीपी|पिन|PIN|सीवीवी|CVV|पासवर्ड|कोड)[^।.!?\n]{0,40}?"
       r"(?:बताएं|बताएँ|बताइए|बताओ|बता\s*दें|बता\s*दो|बता\s*दीजिए|भेजें|भेजिए|भेजो|भेज\s*दें|भेज\s*दो|शेयर\s*करें|शेयर\s*करो|शेयर\s*कीजिए|साझा\s*करें|हमें\s*दें)"),
    rx(rf"\b{_SECRET_LATN}\b[^.!?\n]{{0,40}}?\b(?:batayein|bataye|bataiye|batao|bata\s+do|bata\s+dein|bhejo|bhejein|bhej\s+do|share\s+karo|share\s+karein|share\s+kijiye|dijiye|de\s+do)\b"),
    rx(rf"(?:OTP|ওটিপি|পিন|PIN|সিভিভি|CVV|পাসওয়ার্ড|কোড)[^।.!?\n]{{0,40}}?(?:বলুন|বলো|পাঠান|পাঠাও|পাঠিয়ে\s*দিন|জানান|জানাও|শেয়ার\s*করুন)(?![{BENGALI}])"),
    rx(rf"\b{_SECRET_LATN}\b[^.!?\n]{{0,30}}?\b(?:bolun|bolo|pathan|pathao|janan|janao|share\s+korun)\b"),
]
_DELIVERY_CTX = rx(r"\b(deliver(?:y|ed)?|ride|driver|captain|cab|doorstep|dac)\b|डिलीवरी|राइड|ड्राइवर|कप्तान|ডেলিভারি|রাইড|ড্রাইভার")
_CALL_CTX = rx(r"\b(call|caller|phone|is\s+number|this\s+number|ei\s+number)\b|कॉल|फोन|नंबर\s*पर|কল|ফোন|নম্বরে")

PIN_RECEIVE = [
    rx(r"\b(?:enter|type|put|input)\b\W+(?:[\w']+\W+){0,3}?(?:upi\s*)?(?:m-?)?pin\b.{0,80}?\b(?:receive|get|claim|credit\w*|refund|cashback|accept)\b"),
    rx(r"\b(?:receive|claim|get)\b.{0,60}?\b(?:enter|type)\b\W+(?:[\w']+\W+){0,3}?(?:upi\s*)?pin\b"),
    rx(r"\bapprove\b\W+(?:[\w']+\W+){0,5}?(?:to|and)\s+(?:receive|get|claim)\b"),
    rx(r"\bscan\b.{0,30}\bqr\b.{0,40}\bto\s+(?:receive|get|claim|accept)\b"),
    rx(r"(?:पाने|प्राप्त|रिफंड|कैशबैक|लेने)[^।\n]{0,60}?(?:पिन|PIN)[^।\n]{0,15}?(?:डालें|डालिए|डालो|दर्ज\s*करें)"),
    rx(r"\b(?:receive|paane|pane|lene|refund|cashback)\b.{0,60}?\bpin\b\W+(?:daalein|daalo|dalein|dalo|daale|dale|daaliye|enter\s+karein|enter\s+karo)\b"),
    rx(r"(?:পেতে|গ্রহণ|রিফান্ড|ক্যাশব্যাক|নিতে)[^।\n]{0,60}?(?:পিন|PIN)\s{0,3}(?:দিন|লিখুন)"),
    rx(r"\b(?:refund|nite|pete|cashback|receive)\b.{0,60}?\bpin\b\W+(?:din|likhun|dao)\b"),
    rx(r"(?:\bQR\b|কিউআর|क्यूआर).{0,80}?(?:\bPIN\b|পিন|पिन)"),
]
_REMOTE = r"(?:any\s?desk|team\s?viewer|quick\s?support|rust\s?desk|airdroid|screen[\s-]?shar\w*|स्क्रीन\s*शेयर\w*|স্ক্রিন\s*শেয়ার\w*)"
_INSTALL = r"(?:install\w*|download\w*|open|share\s+korte\s+din|kholo|kholiye|इंस्टॉल|डाउनलोड|ইনস্টল|ডাউনলোড)"
REMOTE = [rx(rf"{_REMOTE}.{{0,50}}?{_INSTALL}|{_INSTALL}.{{0,50}}?{_REMOTE}")]
APK = [rx(r"\.apk\b|\bapk\s+(?:file|फाइल|ফাইল)|एपीके")]

DA_PHRASE = rx(r"digital(?:ly)?\s+arrest\w*|डिजिटल\s*अरेस्ट|ডিজিটাল\s*অ্যারেস্ট")
_AUTH = rx(r"\b(?:police|cbi|ed|enforcement\s+directorate|narcotics|ncb|customs|crime\s+branch|cyber\s*(?:cell|crime)|"
           r"supreme\s+court|high\s+court|court|trai|inspector|dcp|central\s+bureau\s+of\s+investigation|income\s+tax\s+officer)\b|पुलिस|सीबीआई|ईडी|कस्टम|नारकोटिक्स|कोर्ट|इंस्पेक्टर|"
           r"পুলিশ|সিবিআই|কাস্টমস|সাইবার|আদালত|কোর্ট")
_ARREST = rx(r"\b(?:arrest\w*|warrant|giraftari)\b|गिरफ्तार\w*|गिरफ्तारी|वारंट|গ্রেফতার|গ্রেপ্তার|ওয়ারেন্ট")
_COERCE = rx(r"\b(?:video\s*call|skype|camera|stay\s+on\s+(?:the|this)\s+call|(?:don'?t|do\s+not)\s+(?:disconnect|tell|inform|discuss|contact)|"
             r"tell\s+no\s+one|confidential|official\s+secrets|bail|safe\s+account|verification\s+account|video\s+call\s+e)\b|"
             r"kisi\s+(?:ko|se)\s+(?:\w+\s+)?mat|वीडियो\s*कॉल|कॉल\s*मत\s*काट|किसी\s*को\s*न\s*बताएं|जमानत|"
             r"ভিডিও\s*কল|ক্যামেরা|কাউকে\s*(?:কিছু\s*)?বলবেন\s*না")
SAFE_ACC = [rx(r"\b(?:safe|secure|rbi|verification|escrow|government|court)\s+(?:verified\s+)?(?:bank\s+)?(?:account|a/c|khata|khate)\b|"
               r"सुरक्षित\s*खात|आरबीआई\s*खात|RBI\s*खात|নিরাপদ\s*অ্যাকাউন্ট")]
_MONEY_MOVE = rx(r"\b(?:transfer\w*|move|send|deposit|bhej\w*|pathan|pathao|jama)\b|ट्रांसफर|भेज|जमा|পাঠ|জমা|ট্রান্সফার")
_OFFICIAL_FEE = rx(r"\b(?:fine|penalty|challan|duty|tax|bail|jurmana)\b|जुर्माना|चालान|जमानत|शुल्क|জরিমানা|চালান|জামিন|শুল্ক")
_PAY_VERB = rx(r"\b(?:pay|send|transfer|deposit|gpay|google\s+pay|bhejo|bhejein|pathao|pathan|karein)\b|भेजें|भेजो|जमा\s*करें|পাঠান|জমা\s*দিন")
_CREDIT_ALERT = rx(r"\b(?:debited|credited|received|paid\s+to|successful)\b|प्राप्त\s*हुए|जमा\s*(?:किए|हुए)|पेमेंट\s*सफल|জমা\s*হয়েছে|পেয়েছি|সফল")

GUARANTEED = [
    rx(r"\b(?:guarantee[ds]?|sure[\s-]?shot|assured|risk[\s-]?free|zero\s+risk|no\s+risk)\b\W+(?:[\w'%]+\W+){0,4}?(?:returns?|profits?|income|gains?|earnings?)\b"),
    rx(r"\b(?:returns?|profits?|gains?|income)\b\W+(?:[\w'%]+\W+){0,2}?(?:guaranteed|assured)\b"),
    rx(r"(?:\d+(?:\.\d+)?\s?%|\b(?:double|triple|[2-9]x)\b)\W+(?:[\w'%]+\W+){0,4}?(?:daily|a\s+day|per\s+day|every\s+day|weekly|a\s+week|per\s+week|every\s+week|monthly\s+profit|in\s+\d+\s+(?:days|weeks|hours))\b"),
    rx(r"\b(?:daily|weekly|every\s+day|every\s+week|per\s+day|per\s+week)\b\W+(?:[\w'%]+\W+){0,3}?\d+(?:\.\d+)?\s?%"),
    rx(r"\b(?:double|triple|[2-9]x)\s+(?:your\s+)?(?:money|investment|amount|paisa|paise|taka|rupees|cash)\b|\b(?:money|paise|paisa|taka|amount)\s+double\b|\bdouble\s+(?:scheme|hobe|ho\s+jayega)\b"),
    rx(r"(?:पक्का|गारंटी\w*|निश्चित|सुनिश्चित)[^।\n]{0,15}?(?:मुनाफ\w*|रिटर्न|लाभ|कमाई|कमाने|फायदा)|(?:मुनाफ\w*|रिटर्न|कमाई|कमाने)[^।\n]{0,12}?(?:पक्का|गारंटी\w*)"),
    rx(r"(?:रोजाना|रोज|प्रतिदिन|हर\s*दिन|हर\s*हफ्ते|हर\s*महीने|दिन\s*में|महीने\s*में)[^।\n]{0,25}?(?:\d+\s?%|दोगुना|दुगना|डबल)"),
    rx(r"(?:নিশ্চিত|গ্যারান্টি\S*|পাকা)[^।\n]{0,15}?(?:লাভ|রিটার্ন|আয়|মুনাফা)|(?:লাভ|রিটার্ন)[^।\n]{0,10}?(?:নিশ্চিত|গ্যারান্টি\S*)"),
    rx(r"(?:প্রতিদিন|রোজ|প্রতি\s*সপ্তাহে|প্রতি\s*মাসে|এক\s*মাসে|মাসে)[^।\n]{0,25}?(?:\d+\s?%|[০-৯]+\s?%|দ্বিগুণ|ডাবল)"),
    rx(r"\b(?:pakka|guaranteed|guarantee|nishchit)\b\W+(?:[\w%]+\W+){0,2}?(?:profit|returns?|munafa|income|labh|lav|kamai)\b"),
    rx(r"\b(?:protidin|roz|rozana|har\s+din|har\s+mahine|mahine|mash\s*e)\b\W+(?:\w+\W+){0,3}?\d+(?:\.\d+)?\s?%|\d+(?:\.\d+)?\s?%\W+(?:\w+\W+){0,2}?(?:monthly|weekly|daily|roz|protidin)\b"),
]
# Romanised rate patterns ("protidin 10%", "mash e 30%") also match discounts ("ei mash e 50% chhar"),
# found by the held-out run (H197); they count only next to a returns word.
_LATN_RATE = len(GUARANTEED) - 1
_RETURNS_WORD = rx(r"\b(?:profit|returns?|munafa|income|labh|lav|kamai|paben|milega|interest|byaj)\b|লাভ|মুনাফা|आय|मुनाफा|रिटर्न")
TASK = [
    rx(r"\b(?:like|subscribe|rate|rating|review|follow|5[\s-]?star|five[\s-]?star)s?\b\W+(?:[\w'&]+\W+){0,4}?(?:youtube|videos?|hotels?|google\s+maps|maps|instagram|reels?|products?|movies?|restaurants?|pages?|posts?)\b"),
    rx(r"\b(?:youtube|videos?|hotels?|instagram|products?|movies?|restaurants?)\s+(?:reviews?|ratings?|likes?)\b"),
    rx(r"\b(?:prepaid|merchant|vip|recharge)\s+task|\btask\s+(?:level|group)\b|\bunlock\s+(?:your\s+)?(?:withdrawal|commission|earnings)\b"),
    rx(r"(?:लाइक|रिव्यू|रेटिंग|फॉलो|स्टार\s*दें)[^।\n]{0,40}?(?:₹|कमाएं|पाएं|कमाई|रुपये)|प्रीपेड\s*टास्क"),
    rx(r"(?:লাইক|রিভিউ|রেটিং|ফলো)[^।\n]{0,40}?(?:₹|আয়|পাবেন|টাকা|কমিশন)|প্রিপেইড\s*টাস্ক"),
    rx(r"\b(?:like|review|rating|follow|reels)\b.{0,40}?(?:₹|paben|kamao|kamaao|income|milega)|prepaid\s+task"),
]
_EARN = rx(r"₹|\brs\.?\s?\d|\b(?:earn\w*|paid|pays|income|kamao|kamaao|commission|salary|paben|per\s+(?:like|review|follow|rating))\b|"
           r"कमाएं|कमाई|पाएं|আয়|পাবেন|টাকা")

# ---- strong and weak signals ------------------------------------------------------------------
SECRECY = rx(r"\b(?:don'?t|do\s+not)\s+(?:tell|inform)\s+(?:anyone|mom|mum|dad|our\s+parents|parents|family|your\s+family)|"
             r"\btell\s+no\s+one\b|\bkeep\s+(?:this|it)\s+(?:secret|confidential)\b|\b(?:please\s+)?don'?t\s+call\b|"
             r"\bkisi\s+ko\s+mat\s+bata\w*|किसी\s*को\s*मत\s*बता\w*|घर\s*पर\s*किसी\s*को|"
             r"কাউকে\s*(?:কিছু\s*)?(?:বলবেন|বলো|বলিস)\s*না|বাড়িতে\s*কাউকে|\b(?:baba|ma|mummy|papa)\s+ke\s+bolo\s+na\b")
NEW_NUMBER = rx(r"\b(?:new|naya|nayi|notun)\s+number\b|\blost\s+my\s+phone\b|\bphone\s+(?:kho|kharab|hariye|fell|is\s+lost)|"
                r"\bfriend'?s\s+(?:phone|number)\b|\bdost\s+ka\s+number\b|\bbondhur\s+number\b|नया\s*नंबर|फोन\s*खो|নতুন\s*নম্বর|ফোন\s*হারিয়ে")
_MONEY_ASK = rx(r"\b(?:send|transfer|bhej\w*|pathao|pathan|google\s+pay\s+kar|gpay)\b|₹\s?\d|\b\d{3,}\b|भेज|পাঠা")
UPFRONT_FEE = rx(r"\b(?:registration|joining|security|processing|verification|training|slot\s+booking|medical|visa|activation|service|"
                 r"background\s+verification)\s+(?:fee|fees|charge|charges|deposit|kit)\b|\bstarter\s+kit\b|\btraining\s+(?:kit|material)\b|"
                 r"\b(?:fee|fees|advance)\b|फीस|शुल्क|डिपॉजिट|एडवांस|ফি(?![ঀ-৿])|ডিপোজিট|অ্যাডভান্স|\bfee\s+(?:jama|din)\b")
_FEE_CONTEXT = rx(r"\b(?:job|selected|hiring|vacancy|vacancies|offer\s+letter|interview|naukri|loan|prize|lottery|won|refund|withdraw\w*|visa|"
                  r"joining|kaj|kaaj|chakri|work\s+from\s+home|packing|customs|parcel|redelivery)\b|नौकरी|भर्ती|जॉइनिंग|लोन|इनाम|लॉटरी|"
                  r"कस्टम|पार्सल|চাকরি|নিয়োগ|লোন|পুরস্কার|জয়েনিং|কাজ|কাস্টমস|পার্সেল")
PRIZE = rx(r"\b(?:lottery|lucky\s+draw|lucky\s+number|kbc|you\s+(?:have\s+)?won|you'?ve\s+won|scratch\s+card\s+won|jeeta|jeete)\b|"
           r"जीते\s*हैं|लॉटरी|लकी\s*ड्रॉ|लाटरी|লটারি|জিতেছেন|লাকি\s*নম্বর")
DAILY_EARN = rx(r"(?:\bper\s+day\b|\bdaily\b|\ba\s+day\b|/day|\broz\b|\brozana\b|\bprotidin\b|प्रतिदिन|रोज|দৈনিক|প্রতিদিন|রোজ)[^.।\n]{0,25}?"
                r"(?:₹|\brs\b|\bincome\b|\bearn\w*|\bkamai\b|कमाएं|कमाई|आय|আয়|income\s+hobe)|₹\s?[\d,]+[^.।\n]{0,12}?(?:per\s+day|a\s+day|/day|daily)")
URGENCY = rx(r"\b(?:today|tonight|immediately|urgent\w*|within\s+\d+\s+(?:hours?|minutes?|mins?)|right\s+now|last\s+date|"
             r"limited|turant|abhi|jaldi|aaj\s+hi|ekhuni|ajkei)\b|तुरंत|अभी|आज\s*ही|आज\s*रात|जल्दी|এখনই|এক্ষুনি|আজই|আজ\s*রাতে")
THREAT = rx(r"\b(?:blocked|block\s+hobe|suspended|frozen|freeze|deactivated|disconnected|closed|cut\s+off|band\s+ho)\b|"
            r"बंद\s*हो|ब्लॉक|काट\s*दिया|कट\s*जाएगा|বন্ধ\s*হ|ব্লক|কেটে\s*দেওয়া|ফ্রিজ")
OFF_PLATFORM = rx(r"\bt\.me/|\btelegram\b|\bwa\.me/|\bwhatsapp\s+(?:pe|par|kar\w*|e)\b|व्हाट्सऐप\s*(?:करें|पर)|টেলিগ্রাম")
CRYPTO = rx(r"\b(?:crypto|bitcoin|btc|usdt|forex)\b|क्रिप्टो|ফরেক্স|ক্রিপ্টো")
RETURN_REQUEST = rx(r"(?:\bby\s+mistake\b|\baccidentally\s+sent\b|\bgalti\s+se\b|\bbhul\s+kore\b|गलती\s*से|ভুল\s*করে)[^.।\n]{0,80}?"
                    r"(?:\breturn\b|\bsend\s+it\s+back\b|\bwapas\b|\bferot\b|वापस|ফেরত)")
SCREENSHOT_CLAIM = rx(r"(?:screenshot|स्क्रीनशॉट|স্ক্রিনশট)")
_PAID_CLAIM = rx(r"\b(?:paid|payment|sent|kar\s+diya|korechi|bhej\s+diye)\b|भेज|पेमेंट|পেমেন্ট|পাঠিয়ে|পাঠিয়েছি")
WITHDRAW_FEE = rx(r"(?:\bwithdraw\w*|निकालने|विदड्रॉल|তোলার|tulte|nikalne)[^.।\n]{0,40}?(?:\btax\b|\bfee\b|\bcharges?\b|टैक्स|चार्ज|শুল্ক|চার্জ|ট্যাক্স)")
POWER_CUT = [rx(r"(?:electricity|power|bijli|बिजली|বিদ্যুৎ).{0,80}?(?:disconnect\w*|cut|kete|काट|कट|কেটে|কাটা).{0,80}?"
               r"(?:\bcall\b|contact|officer|संपर्क|अधिकारी|কল|যোগাযোগ|অফিসার|call\s+korun)")]
_TONIGHT = rx(r"\btonight\b|\btoday\b|आज\s*रात|आज|aaj\s+raat|আজ\s*রাতে|আজ|\d{1,2}[:.]\d{2}\s*(?:pm|baje|बजे)?")
_PINCODE = rx(r"\bpin\s*code\b|\bpincode\b|पिन\s*कोड|পিন\s*কোড")

# ---- asks: what the message wants the reader to do ---------------------------------------------
# Wide on purpose: a missed ask could turn a real scam into "Can't tell", while an extra one only
# leaves the model's verdict as it was.
ASK_PAY = rx(r"\b(?:pay|gpay|google\s+pay|phonepe|paytm|deposit|donate|chanda|recharge\s+(?:your|now|it|kar\w*|kor\w*)|"
             r"invest\w*|buy|purchase|subscribe|paisa\s+laga\w*|paise\s+laga\w*|taka\s+(?:rakh|laga|khata)\w*|kharid\w*|kinun)\b|"
             r"निवेश|पैसा\s*लगा|पैसे\s*लगा|रुपये\s*लगा|खरीद|বিনিয়োগ|টাকা\s*(?:রাখ|লাগা|খাটা)|কিনুন|কিনে\s*নিন|"
             r"पेमेंट\s*कर|भुगतान\s*कर|जमा\s*कर|रिचार्ज\s*कर|दान\s*कर|পেমেন্ট\s*কর|জমা\s*(?:দিন|দাও|করুন|করে\s*দিন)|"
             r"রিচার্জ\s*কর|চাঁদা|দান\s*কর")
_SEND = rx(r"\b(?:send|transfer|bhej\w*|pathao|pathan|pathiye|pathie|lauta\w*|ferot|return|wapas)\b|भेज|लौटा|वापस|ट्रांसफर|"
           r"পাঠ|ফেরত|ট্রান্সফার")
_MONEY = rx(r"₹|\brs\.?\s?\d|\b(?:rupees?|rupaye|taka|money|paisa|paise|amount|fees?|\d[\d,]{2,})\b|रुपये|रुपए|पैसे|पैसा|फीस|"
            r"টাকা|ফি(?![ঀ-৿])|[०-९]{3,}|[০-৯]{3,}|\b(?:btc|usdt|eth|bitcoin|crypto\w*)\b")
# "₹15,000 dile ... call", "₹৫০,০০০ দিলে জয়েনিং লেটার", "आधा पैसा पहले": paying for an outcome is a pay ask
# too (found on held-out v1). The amount must come first: "give 5 minutes and get ₹100" asks for no money.
_PAY_FOR = rx(r"(?:(?:₹|\brs\.?)\s?[\d०-९০-৯][\d,.०-९০-৯]*|[\d०-९০-৯][\d,.०-९০-৯]*\s*(?:lakh|lac|हजार|लाख|হাজার|লাখ|rupees?|"
              r"rupaye|रुपये|रुपए|টাকা|taka))[^.।!?\n]{0,25}?(?:\b(?:give|dile|diye|din|dao|dena|de\s+do|dijiye|dein|deben)\b|"
              r"देने|दें|दे\s*दो|दीजिए|देना|দিলে|দিন|দাও|দিয়ে|দেবেন|দিতে)|"
              r"(?:पैसा|पैसे|रुपये|টাকা|\bpaisa\b|\bpaise\b|\btaka\b)\s*(?:पहले|\bpehle\b|আগে|\bage\b)")
ASK_LINK = rx(r"\b(?:link|click|tap\s+(?:here|on|the))\b|लिंक|क्लिक|লিঙ্ক|লিংক|ক্লিক")
_MASKED_PHONE = rx(r"(?<![\w])(?:\+?91[\s-]?)?[6-9]\d{3,7}[x×*]{2,}|\[phone\]")   # "[PHONE]": a number masked in real messages
_TOLL_FREE = rx(r"\b1[89]00[\s-]?\d{3}[\s-]?\d{3,4}\b|\b1800[\s-]?\d{4,7}\b")
_DETAIL = rx(r"\b(?:aadhaa?r|pan|kyc|card\s+(?:number|details|no)|cvv|bank\s+(?:details|account)|account\s+(?:number|details|no)|"
             r"date\s+of\s+birth|dob|password|login|net\s*banking|payment\s+details|personal\s+details|card\s+details)\b|"
             r"आधार|पैन|केवाईसी|कार्ड|बैंक\s*(?:खाता|डिटेल|विवरण)|पासवर्ड|আধার|প্যান|কেওয়াইসি|কার্ডের|ব্যাংকের\s*তথ্য|পাসওয়ার্ড")
_DETAIL_VERB = rx(r"\b(?:share|send|update|enter|verify|confirm|provide|give|fill|submit|upload|link|dijiye|bhejein|bhejo|batayein|"
                  r"bataiye|update\s+kar\w*|din|pathan|janan)\b|दें|दीजिए|भेजें|भेजिए|अपडेट|शेयर|बताएं|बताइए|भरें|লিংক|"
                  r"দিন|পাঠান|আপডেট|জানান|শেয়ার|পূরণ")
# Joining a trading-tips or "task" group puts the reader in a room the sender runs; it is where
# investment scams take the money (golden G001: "Join the Nifty Kings WhatsApp group").
ASK_JOIN = rx(r"\bjoin\b\W+(?:[\w'&]+\W+){0,4}?(?:group|channel|community)\b|\b(?:group|channel)\s+(?:join|me\s+jud\w*|e\s+jog\w*)|"
              r"ग्रुप\s*(?:में|से)\s*(?:जुड़|जुड|शामिल)|(?:গ্রুপে|চ্যানেলে)\s*(?:যোগ|জয়েন)")
ASK_INSTALL = rx(r"\b(?:install\w*|download\w*)\b|इंस्टॉल|डाउनलोड|ইনস্টল|ডাউনলোড|\.apk\b|any\s?desk|team\s?viewer")
ASK_QR = rx(r"\bqr\b|क्यूआर|কিউআর|\bscan\b|स्कैन|স্ক্যান")
ASK_CONTACT = rx(r"\b(?:call\s+(?:me|us|back|now|karein|karo|kijiye|korun|koro|kar)|contact|reach\s+(?:me|us)|press\s+\d|dial|"
                 r"whatsapp\s+(?:me|us|pe|par|e|kar\w*|kor\w*)|sampark|jogajog|reply)\b|कॉल\s*कर|संपर्क|दबाएं|दबाइए|बात\s*कीजिए|"
                 r"কল\s*কর|যোগাযোগ|টিপুন|চাপুন|কথা\s*বল|রিপ্লাই")
_INDIC_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯०१२३४५६७८९", "01234567890123456789")
_CALL_ASKED = {"money_transfer": "pay", "otp_pin": "share_secret", "install_app": "install_app",
               "personal_details": "share_details", "stay_on_call": "stay_on_call"}

_TYPE_WORDS = {
    "digital_arrest": r"\b(?:arrest|warrant|cbi|narcotics|ncb|enforcement\s+directorate|cyber\s+crime|crime\s+branch|court)\b|गिरफ्तार|वारंट|सीबीआई|पुलिस|কোর্ট|গ্রেফতার|সিবিআই|পুলিশ|digital\s+arrest",
    "investment": r"\b(?:invest\w*|trading|trade[sr]?|stocks?|shares?|ipo|crypto|bitcoin|profit|returns?|forex|sebi|task|likes?|reviews?|ratings?|scheme|mining|nifty|algo)\b|निवेश|शेयर|ट्रेडिंग|मुनाफा|टास्क|লাভ|বিনিয়োগ|শেয়ার|ট্রেডিং|টাস্ক|munafa",
    "fake_payment": r"\b(?:by\s+mistake|galti\s+se|bhul\s+kore|refund|cashback|qr|screenshot|olx|quikr|collect\s+request|scratch\s+card)\b|गलती\s*से|रिफंड|कैशबैक|स्क्रीनशॉट|ভুল\s*করে|রিফান্ড|স্ক্রিনশট",
    "fake_job": r"\b(?:job|hiring|salary|offer\s+letter|vacancy|work\s+from\s+home|naukri|chakri|recruit\w*|selected)\b|नौकरी|भर्ती|सैलरी|চাকরি|নিয়োগ",
    "family_emergency": r"\b(?:mum|mom|mummy|dad|papa|son|daughter|beta|accident|hospital|nephew|didi|mama|kaku|chacha)\b|माँ|पापा|बेटा|बेटे|अस्पताल|एक्सीडेंट|চাচা|মা|বাবা|হাসপাতাল|মামা",
    "parcel": r"\b(?:parcel|courier|shipment|consignment|customs\s+duty|redelivery|india\s+post|fedex|dtdc|blue\s*dart)\b|पार्सल|कूरियर|পার্সেল|কুরিয়ার|শিপমেন্ট",
    "bill_challan": r"\b(?:electricity|bill|challan|fastag|gas\s+connection|dth|sim|power)\b|बिजली|चालान|गैस|বিদ্যুৎ|চালান|গ্যাস",
    "bank_kyc": r"\b(?:kyc|bank|account|card|reward\s+points?|pan|yono|net\s*banking|cvv|otp)\b|खाता|बैंक|कार्ड|ব্যাংক|ব্যাঙ্ক|অ্যাকাউন্ট|কার্ড",
    "other": r"\b(?:lottery|prize|loan|kbc|video)\b|लॉटरी|इनाम|লটারি|পুরস্কার",
}
_TYPE_RX = {k: rx(v) for k, v in _TYPE_WORDS.items()}
# "safe_account" is not here: an "escrow account" can be an investment scam too (held-out H012).
_HARD_TYPE = {"guaranteed_returns": "investment", "task_scam": "investment", "digital_arrest": "digital_arrest",
              "pin_to_receive": "fake_payment", "official_fee_personal_upi": "bill_challan",
              "power_cut_threat": "bill_challan"}


def guess_type(text: str) -> str:
    """Keyword vote for a scam type; used when the model gives none."""
    t = norm(text)
    scores = {k: len(p.findall(t)) for k, p in _TYPE_RX.items()}
    best = max(scores, key=lambda k: (scores[k], -list(_TYPE_RX).index(k)))
    return best if scores[best] else "other"


def _link_flags(text: str, res: RuleResult) -> None:
    for host, full in urls(text):
        if is_official(host):
            res.genuine.append(Flag("official_link", full))
            continue
        tld = host.rsplit(".", 1)[-1]
        compact = host.replace("-", "").replace(".", "")
        if host in SHORTENERS or tld in RISKY_TLDS:
            res.strong.append(Flag("risky_link", full))
        elif any(tok in compact for tok in BRAND_TOKENS):
            res.strong.append(Flag("lookalike_domain", full))
        elif any(tok in compact for tok in LURE_TOKENS):
            res.strong.append(Flag("lure_link", full))


def _ask_flags(raw: str, t: str, call: dict | None, secret, personal_upis: list[str], res: RuleResult) -> None:
    def add(code, m=None):
        res.asks.append(Flag(code, _q(m) if m is not None and hasattr(m, "group") else ""))

    for a in (call or {}).get("asked") or []:
        if a in _CALL_ASKED:
            add(_CALL_ASKED[a])
    if (call or {}).get("safe_account"):
        add("pay")
    if (m := ASK_PAY.search(t)) or personal_upis:
        add("pay", m)
    elif (m := _SEND.search(t)) and _MONEY.search(t):
        add("pay", m)
    elif (m := _PAY_FOR.search(t)):
        add("pay", m)
    if urls(raw) or (m := ASK_LINK.search(t)):
        add("link", m if not urls(raw) else None)
    digits = raw.translate(_INDIC_DIGITS)
    if PHONE_RE.search(digits) or _MASKED_PHONE.search(digits) or _TOLL_FREE.search(digits):
        add("call_number")
    if secret:
        add("share_secret", secret)
    for sentence in re.split(r"[.!?।\n]+", t):
        if (m := _DETAIL.search(sentence)) and _DETAIL_VERB.search(sentence):
            add("share_details", m)
            break
    if (m := ASK_JOIN.search(t)):
        add("join_group", m)
    if (m := ASK_INSTALL.search(t)):
        add("install_app", m)
    if (m := ASK_QR.search(t)):
        add("scan_qr", m)
    if (m := ASK_CONTACT.search(t)):
        add("contact", m)


def _call_flags(call: dict, res: RuleResult) -> None:
    asked = set(call.get("asked") or [])
    claimed, threat = call.get("claimed"), call.get("threat")
    if "otp_pin" in asked:
        res.hard.append(Flag("asks_secret"))
    if "install_app" in asked:
        res.hard.append(Flag("remote_access"))
    if call.get("safe_account"):
        res.hard.append(Flag("safe_account"))
    if claimed in ("police_cbi_customs", "telecom_trai", "courier") and threat == "arrest_case" and (
            call.get("video_or_secret") or "stay_on_call" in asked):
        res.hard.append(Flag("digital_arrest"))
    if claimed == "family_friend" and "money_transfer" in asked and (call.get("video_or_secret") or threat == "family_harm"):
        res.strong.append(Flag("family_pressure"))
    if claimed in ("police_cbi_customs", "bank_rbi", "telecom_trai", "courier") and "money_transfer" in asked:
        res.strong.append(Flag("official_asks_money"))


def scan(text: str, call: dict | None = None) -> RuleResult:
    """Run every rule on the raw (unmasked) text and, for calls, on the structured answers."""
    raw = text or ""
    t = _PINCODE.sub("postcode", norm(raw))
    res = RuleResult()

    inj = find_injection(raw)
    if inj:
        res.hard.append(Flag("injection", inj))

    m = secret = _first(SECRET, t)
    if m and _DELIVERY_CTX.search(t) and not _CALL_CTX.search(t):
        # Delivery and ride OTPs are meant to be given to the agent at the door: a known genuine pattern.
        res.genuine.append(Flag("delivery_otp", _q(m)))
    elif m:
        res.hard.append(Flag("asks_secret", _q(m)))
    if (m := _first(PIN_RECEIVE, t, neg=False, aware=True)):
        res.hard.append(Flag("pin_to_receive", _q(m)))
    if (m := _first(REMOTE, t)):
        res.hard.append(Flag("remote_access", _q(m)))
    if (m := _first(APK, t)):
        res.hard.append(Flag("apk_file", _q(m)))

    if not _AWARE.search(t):
        m = DA_PHRASE.search(t)
        if m or (_AUTH.search(t) and _ARREST.search(t) and _COERCE.search(t)):
            res.hard.append(Flag("digital_arrest", _q(m or _ARREST.search(t))))
    if _MONEY_MOVE.search(t) and (m := _first(SAFE_ACC, t, aware=True)):
        res.hard.append(Flag("safe_account", _q(m)))
    personal_upis = [f"{u}@{h}" for u, h in upi_ids(raw) if not h.startswith("valid")]
    if personal_upis and _OFFICIAL_FEE.search(t) and _PAY_VERB.search(t) and not _CREDIT_ALERT.search(t):
        res.hard.append(Flag("official_fee_personal_upi", personal_upis[0]))
    if _TONIGHT.search(t) and (m := _first(POWER_CUT, t, neg=False, aware=True)):
        res.hard.append(Flag("power_cut_threat", _q(m)))
    if not _YEARLY_PRODUCT.search(t) and (m := _first(GUARANTEED[:_LATN_RATE], t, neg=False, aware=True)):
        res.hard.append(Flag("guaranteed_returns", _q(m)))
    elif not _YEARLY_PRODUCT.search(t) and _RETURNS_WORD.search(t) and (m := _first(GUARANTEED[_LATN_RATE:], t, neg=False, aware=True)):
        res.hard.append(Flag("guaranteed_returns", _q(m)))
    if (m := _first(TASK, t, neg=False, aware=True)) and _EARN.search(t):
        res.hard.append(Flag("task_scam", _q(m)))

    if call:
        _call_flags(call, res)

    # strong signals
    if (m := RETURN_REQUEST.search(t)) and not _AWARE.search(t):
        res.strong.append(Flag("return_request", _q(m)))
    if (m := SCREENSHOT_CLAIM.search(t)) and _PAID_CLAIM.search(t):
        res.strong.append(Flag("screenshot_claim", _q(m)))
    if (m := WITHDRAW_FEE.search(t)):
        res.strong.append(Flag("withdrawal_fee", _q(m)))
    if (m := SECRECY.search(t)):
        res.strong.append(Flag("secrecy", _q(m)))
    if (m := NEW_NUMBER.search(t)) and _MONEY_ASK.search(t):
        res.strong.append(Flag("new_number_money", _q(m)))
    if (m := _first([UPFRONT_FEE], t, neg=False)) and _FEE_CONTEXT.search(t) and not re.search(r"\bno\s+fee|no fee|कोई\s*फीस\s*नहीं|ফি\s*লাগবে\s*না|never\s+charge", t, re.I):
        res.strong.append(Flag("upfront_fee", _q(m)))
    if personal_upis and _PAY_VERB.search(t) and not _CREDIT_ALERT.search(t):
        res.strong.append(Flag("personal_upi_payment", personal_upis[0]))
    if (m := PRIZE.search(t)) and not _AWARE.search(t):
        res.strong.append(Flag("prize_lottery", _q(m)))
    if (m := DAILY_EARN.search(t)) and not _AWARE.search(t):
        res.strong.append(Flag("daily_earnings", _q(m)))
    _link_flags(raw, res)
    _ask_flags(raw, t, call, secret, personal_upis, res)

    # weak signals
    for code, p in (("urgency", URGENCY), ("threat_block", THREAT), ("off_platform", OFF_PLATFORM), ("crypto", CRYPTO)):
        if (m := p.search(t)):
            res.weak.append(Flag(code, _q(m)))
    if _AWARE.search(t):
        res.genuine.append(Flag("awareness"))

    # de-duplicate by code, keeping the first quote
    for tier in ("hard", "strong", "weak", "genuine", "asks"):
        seen, kept = set(), []
        for f in getattr(res, tier):
            if f.code not in seen:
                seen.add(f.code)
                kept.append(f)
        setattr(res, tier, kept)

    for f in res.hard:
        if f.code in _HARD_TYPE:
            res.type_hint, res.type_fixed = _HARD_TYPE[f.code], True
            break
    if res.type_hint is None and (res.hard or res.strong):
        res.type_hint = guess_type(raw + " " + " ".join(str(v) for v in (call or {}).values()))
    return res
