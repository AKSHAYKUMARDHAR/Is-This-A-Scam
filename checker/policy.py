"""Verdict policy: rule flags and model samples in, one of three verdicts out.

1. A hard rule flag decides "scam" (PRD decision rule 1).
2. Too little text, or no model answer, is "unsure".
3. Self-consistency: every sample must agree on the label, otherwise "unsure" (rule 2).
4. Agreement still needs mean confidence at or above a threshold chosen on the golden set (rule 3).
5. "no_signs" is also blocked by any strong rule signal, so a message with a real warning sign is
   never cleared.
6. A payment-confirmation screenshot is always "unsure" unless a hard flag fires: a screenshot can
   neither prove nor disprove a payment, so the answer is to check your own UPI app.
7. A known genuine pattern (a delivery or ride OTP for the agent at the door, with no call involved)
   caps a model-only "scam" at "unsure". It never clears a message.
8. A model-only "scam" also needs something to warn against: a risky ask in the message (pay, open a
   link, call a number given in it, share a code or personal details, install an app, scan a QR code)
   or a strong rule signal. Without one ("Hi, is this Neha?", "this is my new number, save it") the
   message can't cost anything yet, so the answer is "Can't tell" with how to check, and the
   follow-up that does ask can be checked again. Held-out v1 failed its ambiguous-message check on
   exactly these first-contact openers.
"""
from collections import Counter
from dataclasses import dataclass

from . import config
from .rules import RuleResult
from .taxonomy import SCAM_TYPES


@dataclass
class Decision:
    verdict: str            # scam | unsure | no_signs
    reason: str             # why, for logs and the eval (never shown as thresholds to users)
    scam_type: str | None
    mean_confidence: float | None = None


def clean_sample(sample: dict) -> dict | None:
    """Validate one model answer; None if it is unusable."""
    if not isinstance(sample, dict) or sample.get("label") not in ("scam", "genuine", "unsure"):
        return None
    conf = sample.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        return None
    out = dict(sample)
    out["confidence"] = min(max(float(conf), 0.0), 1.0)
    if out.get("scam_type") not in SCAM_TYPES + ["none"]:
        out["scam_type"] = "other" if out["label"] == "scam" else "none"
    return out


def _model_type(samples: list[dict]) -> str | None:
    types = [s.get("scam_type") for s in samples if s.get("scam_type") not in (None, "none")]
    return Counter(types).most_common(1)[0][0] if types else None


def decide(rules: RuleResult, samples: list[dict], *, input_ok: bool = True, screen_kind: str | None = None,
           scam_threshold: float | None = None, genuine_threshold: float | None = None) -> Decision:
    t_scam = config.SCAM_THRESHOLD if scam_threshold is None else scam_threshold
    t_gen = config.GENUINE_THRESHOLD if genuine_threshold is None else genuine_threshold
    samples = [s for s in (clean_sample(x) for x in samples) if s]

    if rules.hard:
        scam_type = rules.type_hint if rules.type_fixed else (_model_type(samples) or rules.type_hint or "other")
        return Decision("scam", "hard_flag", scam_type)
    if not input_ok:
        return Decision("unsure", "too_short", None)
    if screen_kind == "payment_confirmation":
        # PRD: a screenshot can never prove (or disprove) a payment; the answer is "check your own app".
        return Decision("unsure", "payment_screenshot", "fake_payment")
    if not samples:
        return Decision("unsure", "model_unavailable", None)

    labels = {s["label"] for s in samples}
    mean = sum(s["confidence"] for s in samples) / len(samples)
    if len(labels) > 1:
        return Decision("unsure", "disagreement", _model_type(samples), mean)
    label = labels.pop()
    if label == "scam" and "delivery_otp" in rules.codes("genuine") and not rules.strong:
        # Golden v1's only false alarm: a delivery OTP for the agent at the door, called a scam by the
        # model. The rules know this genuine pattern, so the model alone can't call it a scam.
        return Decision("unsure", "known_genuine_pattern", None, mean)
    if label == "scam" and not rules.strong and not rules.risky_ask():
        return Decision("unsure", "no_risky_ask", _model_type(samples), mean)
    if label == "scam":
        if mean >= t_scam:
            return Decision("scam", "agreement", _model_type(samples) or rules.type_hint or "other", mean)
        return Decision("unsure", "low_confidence", _model_type(samples), mean)
    if label == "genuine":
        if rules.strong:
            return Decision("unsure", "strong_signal", rules.type_hint, mean)
        if mean >= t_gen:
            return Decision("no_signs", "agreement", None, mean)
        return Decision("unsure", "low_confidence", None, mean)
    return Decision("unsure", "model_unsure", _model_type(samples), mean)
