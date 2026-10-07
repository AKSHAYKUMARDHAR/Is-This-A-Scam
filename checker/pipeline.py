"""One check, end to end: input -> rules (raw text, local) -> masking -> model samples -> verdict -> card.

Self-consistency with early stop: the first two samples run in parallel; if they disagree the
verdict is already "Can't tell", so the third is skipped. This gives the same verdicts as always
running all three, at about two thirds of the cost on ambiguous messages.

Messages with a hard rule flag still get one model call, for the scam type and an explanation in
the user's language; the verdict does not depend on it. Messages with an injection attempt are
never shown to the model at all.
"""
import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field

from . import advice, config, lang as langmod, masking, policy, rules
from .llm import LLMError, Provider, QuotaExhausted
from .prompts import user_message
from .taxonomy import HEADLINES, LANGS, TYPE_LABELS, VERDICT_LABELS
from .text_utils import norm

CLAIMED = {
    "police_cbi_customs": "police, CBI, customs, ED or a court", "bank_rbi": "a bank or RBI",
    "telecom_trai": "TRAI or a telecom company", "courier": "a courier company", "family_friend": "a family member or friend",
    "company_hr": "a company or an HR recruiter", "other": "someone else, or not sure",
}
ASKED = {
    "money_transfer": "transfer money", "otp_pin": "share an OTP, PIN or card details", "install_app": "install an app",
    "personal_details": "personal details (Aadhaar, bank details or date of birth)",
    "stay_on_call": "stay on the call or keep the camera on", "nothing": "nothing yet",
}
THREAT = {"arrest_case": "arrest or a legal case", "account_block": "blocking an account, card or SIM",
          "family_harm": "harm to a family member", "none": "no threat"}


@dataclass
class CheckInput:
    kind: str = "text"                 # text | call | image
    text: str = ""
    call: dict | None = None
    image: bytes | None = None
    image_mime: str = "image/png"
    ui_lang: str = "auto"              # auto | en | hi | bn


@dataclass
class CheckTrace:
    """What happened inside a check, for logs and the eval. Contains no message text."""
    samples: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def describe_call(call: dict) -> str:
    asked = [ASKED.get(a, a) for a in call.get("asked") or []] or ["nothing yet"]
    lines = [
        "Answers about a phone call the person received:",
        f"- The caller claimed to be: {CLAIMED.get(call.get('claimed'), 'not said')}",
        f"- They asked the person to: {'; '.join(asked)}",
        f"- Threat made: {THREAT.get(call.get('threat'), 'not said')}",
        f"- Video call, or asked to stay on the call or keep it secret: {'yes' if call.get('video_or_secret') else 'no'}",
        f"- Asked to move money to a 'safe', 'RBI' or 'verification' account: {'yes' if call.get('safe_account') else 'no'}",
    ]
    details = (call.get("details") or "").strip()
    if details:
        lines.append(f"- In the person's own words: {details}")
    return "\n".join(lines)


def _enough_text(text: str) -> bool:
    return len(re.findall(r"\w", text or "")) >= 12


async def _sample(provider: Provider, prompt: str, trace: CheckTrace) -> dict | None:
    trace.calls += 1
    try:
        out, usage = await provider.classify(prompt)
    except QuotaExhausted:
        raise
    except LLMError as e:
        trace.errors.append(str(e)[:200])
        return None
    trace.input_tokens += usage.get("input_tokens", 0)
    trace.output_tokens += usage.get("output_tokens", 0)
    cleaned = policy.clean_sample(out)
    if cleaned is None:
        trace.errors.append("unusable model answer")
    return cleaned


async def self_consistency(provider: Provider, prompt: str, n: int, trace: CheckTrace) -> list[dict]:
    """Up to n samples; stops as soon as two disagree or a call fails."""
    first = min(2, n)
    got = await asyncio.gather(*[_sample(provider, prompt, trace) for _ in range(first)])
    samples = [s for s in got if s]
    if len(samples) < first or len({s["label"] for s in samples}) > 1:
        return samples
    for _ in range(n - first):
        s = await _sample(provider, prompt, trace)
        if s is None:
            break
        samples.append(s)
        if s["label"] != samples[0]["label"]:
            break
    return samples


def _quote_ok(quote: str, source: str) -> bool:
    q = re.sub(r"\s+", " ", norm(quote)).strip().lower()
    s = re.sub(r"\s+", " ", norm(source)).lower()
    return len(q) >= 3 and q in s


def build_card(decision: policy.Decision, rule_res: rules.RuleResult, samples: list[dict], source_text: str,
               out_lang: str, screen_kind: str | None = None) -> dict:
    verdict = decision.verdict
    want = {"scam": "scam", "no_signs": "genuine"}.get(verdict)
    explain = next((s for s in samples if s["label"] == want), None) if want else (samples[0] if samples else None)

    flags: list[dict] = []
    if verdict != "no_signs":
        for f in rule_res.hard + rule_res.strong:
            why = advice.flag_why(f.code, out_lang)
            if why:
                flags.append({"quote": f.quote if f.quote and _quote_ok(f.quote, source_text) else "", "why": why})
        if explain:
            for rf in explain.get("red_flags") or []:
                quote, why = str(rf.get("quote", "")).strip(), str(rf.get("why", "")).strip()
                if why and _quote_ok(quote, source_text) and all(quote.lower() not in x["quote"].lower() for x in flags if x["quote"]):
                    flags.append({"quote": quote, "why": why})
    flags = flags[:4]

    genuine_signs = [str(g) for g in (explain or {}).get("genuine_signs") or []][:3] if verdict != "scam" else []
    if decision.reason == "too_short":
        summary = advice.TOO_SHORT[out_lang]
    elif explain and explain.get("summary") and "injection" not in rule_res.codes("hard"):
        summary = str(explain["summary"]).strip()
    else:
        summary = HEADLINES[verdict][out_lang]
    scam_type = decision.scam_type if verdict == "scam" else (decision.scam_type if verdict == "unsure" else None)
    verify = advice.verify_tip(scam_type if verdict != "no_signs" else "other", out_lang)
    if screen_kind == "payment_confirmation":
        verify = advice.SCREENSHOT_NOTE[out_lang]

    return {
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict][out_lang],
        "headline": HEADLINES[verdict][out_lang],
        "scam_type": scam_type if verdict == "scam" else None,
        "scam_type_label": TYPE_LABELS[scam_type][out_lang] if verdict == "scam" and scam_type else None,
        "summary": summary,
        "red_flags": flags,
        "genuine_signs": genuine_signs,
        "next_steps": advice.next_steps(verdict, out_lang),
        "verify": verify,
        "disclaimer": advice.DISCLAIMER[out_lang],
        "share_text": advice.share_text(verdict, scam_type if verdict == "scam" else None, out_lang),
        "lang": out_lang,
    }


async def run_check(inp: CheckInput, provider: Provider | None, *, samples: int | None = None,
                    explain_hard: bool = True) -> tuple[dict, CheckTrace]:
    """Returns (card, trace). Raises QuotaExhausted only from the model layer; everything else degrades to "Can't tell"."""
    started = time.monotonic()
    trace = CheckTrace()
    screen_kind = None

    if inp.kind == "call":
        call = inp.call or {}
        raw = (call.get("details") or "")[: config.MAX_TEXT_CHARS]
        model_text = describe_call({**call, "details": raw})
    elif inp.kind == "image":
        call = None
        raw = ""
        if provider and inp.image:
            trace.calls += 1
            try:
                transcript, usage = await provider.transcribe(inp.image, inp.image_mime)
                raw = str(transcript.get("text", ""))[: config.MAX_TEXT_CHARS]
                screen_kind = transcript.get("screen_kind")
                trace.input_tokens += usage.get("input_tokens", 0)
                trace.output_tokens += usage.get("output_tokens", 0)
            except QuotaExhausted:
                raise
            except LLMError as e:
                trace.errors.append(f"transcribe: {str(e)[:150]}")
        model_text = raw
    else:
        call = None
        raw = (inp.text or "").strip()[: config.MAX_TEXT_CHARS]
        model_text = raw

    detected = langmod.detect(raw)
    out_lang = inp.ui_lang if inp.ui_lang in LANGS else langmod.base(detected)
    rule_res = rules.scan(raw, call)
    input_ok = inp.kind == "call" or _enough_text(raw)
    masked, _ = masking.mask(model_text)
    prompt = user_message(masked, inp.kind, out_lang, screen_kind)

    model_samples: list[dict] = []
    if provider and input_ok and "injection" not in rule_res.codes("hard"):
        if rule_res.hard:
            if explain_hard:
                s = await _sample(provider, prompt, trace)
                model_samples = [s] if s else []
        else:
            model_samples = await self_consistency(provider, prompt, samples or config.SAMPLES, trace)
    trace.samples = model_samples

    # A hard verdict ignores the explanation sample's label; other verdicts use all samples.
    decision = policy.decide(rule_res, [] if rule_res.hard else model_samples, input_ok=input_ok, screen_kind=screen_kind)
    if rule_res.hard and not rule_res.type_fixed:
        decision.scam_type = policy._model_type(model_samples) or rule_res.type_hint or "other"
    card = build_card(decision, rule_res, model_samples, raw, out_lang, screen_kind)
    card.update({
        "check_id": uuid.uuid4().hex[:12],
        "reason": decision.reason,
        "detected_lang": detected,
        "input_kind": inp.kind,
        "screen_kind": screen_kind,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "hard_flags": rule_res.codes("hard"),
    })
    return card, trace
