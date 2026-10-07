# Is This a Scam?

A scam checker for India in **Hindi, Bengali and English**. Paste a suspicious message, upload a
screenshot, or answer five questions about a phone call. You get one of three verdicts, the red
flags quoted from your own message, and what to do next. It never says "safe": when the evidence is
thin it says **"Can't tell, verify it yourself"** instead of guessing.

- Product requirements: [docs/PRD.md](docs/PRD.md) ([live doc](https://claude.ai/code/artifact/5868d9dc-3379-41da-9a35-3a2f6e0fa4ef))
- Built with Claude Code, on the pattern of my [UPI Triage Agent](https://github.com/AKSHAYKUMARDHAR/UPI-Triage-Agent):
  deterministic rules for what is certain, an LLM for the rest, an input guard outside the model,
  and a release gate on a held-out set.

<p>
  <img src="docs/img/app-scam-hi.png" alt="A Hindi verdict card: Likely scam, with three red flags quoted from the message and the next steps" width="32%">
  <img src="docs/img/app-unsure-en.png" alt="An English 'Can't tell' card that explains a short link and shows how to check safely" width="32%">
  <img src="docs/img/app-call-bn.png" alt="The five phone-call questions in Bengali, with answers selected" width="32%">
</p>

RESULTS_PLACEHOLDER

## How it works

```
 message / screenshot / call answers                       web app (Hindi, Bengali, English)
          │                                                 verdict-first vs explanation-first A/B
          ▼
 FastAPI /api/check ──► rate limit (30/h per IP), cache by hash, duplicate-burst flag
          │
          ├─ screenshot ─► model reads the text (image discarded) ─┐
          ▼                                                        ▼
 rules.scan(raw text, locally)          injection guard ──► hard flag: never shown to the model
   hard flags   ─────────────────────────────────────────►  "Likely scam" (1 model call for the explanation)
   strong flags ── block "No scam signs found"
          │
 masking: card, account, ID, phone, OTP, PAN numbers ──► model sees placeholders only
          │
 self-consistency: 2 runs in parallel ─ disagree ─► "Can't tell"   (third run skipped)
          │ agree
          ▼
 3rd run ─ all agree and mean confidence ≥ threshold ─► "Likely scam" / "No scam signs found"
          │ otherwise
          ▼
 "Can't tell"
          │
 card: verdict, type, red flags (model quotes checked against the message), fixed next steps,
       how to verify, share text without the message ──► event log (no message text)
```

| Part | What it does | File |
|---|---|---|
| Rules | 11 hard rules (OTP/PIN requests, PIN to receive money, remote-access apps, .apk files, digital arrest, "safe account" transfers, official fines to personal UPI IDs, guaranteed returns, task scams, power-cut threats, injection) and 18 strong or weak signals, each checked for negation and awareness wording, in Hindi, Bengali, English and romanised Hindi and Bengali | [checker/rules.py](checker/rules.py) |
| Injection guard | Instruction-like text aimed at an AI checker, in all five scripts, decided before the model | [checker/guard.py](checker/guard.py) |
| Masking | Card, Aadhaar-like, account, phone, OTP and PAN numbers are replaced before any model call; links, amounts and UPI IDs are kept because they are evidence | [checker/masking.py](checker/masking.py) |
| Model | Gemini free tier (published runs) or Claude (structured output, adaptive thinking at low effort, refusal fallback); JSON schema with a closed list of labels | [checker/llm.py](checker/llm.py), [checker/prompts.py](checker/prompts.py) |
| Policy | The PRD's decision rules: hard flag, then unanimity, then thresholds; strong signals and payment screenshots can never be cleared | [checker/policy.py](checker/policy.py) |
| Advice | Next steps, verification tips and red-flag explanations are fixed templates in three languages, so the checker never invents a phone number or link | [checker/advice.py](checker/advice.py) |
| API and app | FastAPI service, vanilla JS front end, event log and the PRD's metrics at `/api/stats` | [api/](api/), [web/](web/) |
| Eval | Same code path as production through a caching model wrapper; versions A/B/C, threshold sweep, release gate | [eval/run_eval.py](eval/run_eval.py) |

## Product decisions, and why

- **Three verdicts, never "safe".** One wrong "scam" on a genuine bank message costs more trust than ten honest "can't tell" answers, and a green "safe" teaches people to stop checking. "No scam signs found" is grey and always carries "that isn't a guarantee".
- **Rules decide the cases that are always fraud.** A bank never asks for an OTP and you never need a PIN to receive money, so those patterns skip the model's judgement. Every hard rule is tested against genuine look-alikes: OTP messages that say "do not share", delivery and ride OTPs that you *do* give to the agent, police advisories about digital arrest, FD adverts with "% p.a.", postal PIN codes.
- **Self-consistency instead of self-reported confidence.** A model's own confidence is poorly calibrated, so a firm verdict needs agreement across runs. Disagreement is itself the signal for "can't tell", which also lets the third run be skipped.
- **The guard sits outside the model.** The UPI agent showed that "treat the content as data" in a system prompt does not stop an injection. Here an injection attempt never reaches the model and counts as a red flag in its own right.
- **Advice is never generated.** The model writes the summary and explains red flags; it never writes next steps, phone numbers or links. Its quotes are checked against the user's message and dropped if they do not appear.
- **A screenshot can't prove a payment.** Payment screens always get "Can't tell, check your own UPI app", unless a hard rule fires (the shopkeeper persona in the PRD).
- **The share card never includes the message**, so a parent's personal details don't land in a family group.
- **Web first, WhatsApp bot later.** A bot needs Meta business verification and per-conversation fees; the share card carries the tool into WhatsApp groups for free. The bot is gated on a 15% share rate.

## Run it locally

Python 3.12.

```bash
python -m venv .venv
.venv\Scripts\activate                     # Windows; source .venv/bin/activate elsewhere
pip install -r requirements.txt
copy .env.example .env                     # add a free GEMINI_API_KEY (or ANTHROPIC_API_KEY)
uvicorn api.main:app --reload              # http://localhost:8000
python -m pytest -q                        # 76 tests, no API key needed
```

With no key the app runs rules-only: clear scam patterns are caught, everything else is "Can't tell".

```bash
python -m scripts.try_check "Your SBI KYC expires today, update at sbi-kyc.xyz"   # one check from the CLI
python -m eval.rules_report eval/data/golden.jsonl                                # rules only, no model
python -m eval.run_eval eval/data/golden.jsonl --sweep                            # full eval (cached answers are reused)
python -m eval.run_eval eval/data/holdout.jsonl --gate --offline                  # reproduce the held-out result from the cache
```

## Deploy

`render.yaml` deploys the Docker image to Render's free plan: New > Blueprint > this repo, then paste
`GEMINI_API_KEY`. `/api/stats` is protected by a generated `STATS_TOKEN` (send it as `X-Stats-Token`).
The free plan's disk is not persistent, so the event log resets on restart; attach a disk or a
database before relying on the launch metrics.

## API

| Method | Path | Body / response |
|---|---|---|
| POST | `/api/check` | `{"kind": "text", "text": "..."}`, `{"kind": "call", "call": {"claimed", "asked", "threat", "video_or_secret", "safe_account", "details"}}` or `{"kind": "image", "image_b64": "...", "image_mime": "image/png"}`, plus `lang` (`auto`, `en`, `hi`, `bn`), `client_id`, `variant`. Returns the card: `verdict`, `verdict_label`, `scam_type_label`, `summary`, `red_flags[{quote, why}]`, `genuine_signs`, `next_steps`, `verify`, `share_text`, `disclaimer`, `check_id` |
| POST | `/api/feedback` | `{"event": "helpful" \| "not_helpful" \| "wrong_verdict" \| "stopped_me" \| "shared" \| ..., "check_id": "..."}` |
| GET | `/api/stats` | checks, unique and returning users, helpful rate, share rate, wrong-verdict rate, "stopped me" count, can't-tell rate and p95 latency, overall, last 7 days and per A/B variant |
| GET | `/api/config` | languages, urgent steps, whether a model is configured |

## Project structure

```
checker/   rules, guard, masking, language detection, model providers, policy, advice, pipeline
api/       FastAPI app, rate limit / cache / burst detection, event log and metrics
web/       index.html, styles.css, i18n.js (English, Hindi, Bengali), app.js
eval/      data/ (golden, holdout, injection), run_eval.py, rules_report.py, cache/, results/
tests/     76 tests: text utilities, rules, policy and pipeline (scripted model), API
docs/      PRD and images
```
