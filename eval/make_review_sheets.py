"""Build the review sheets in review/ for the people-checks the eval can't do itself.

    python -m eval.make_review_sheets

- explanations_hi.csv, explanations_bn.csv: 30 cards each, as the app shows them, built from the
  cached model answers (no model calls), for a native speaker to check meaning and wording.
- ui_text.csv: every fixed piece of text in the app (advice, labels, interface), English next to
  Hindi and Bengali.
- labelling_sheet.csv + labelling_key.csv: 60 messages without their labels, for a second person to
  label; eval/agreement.py compares their labels with the dataset's.
- real_messages_template.csv: where to collect real messages; eval/ingest_real.py masks them.

The sheets are CSV with a byte-order mark, so Excel and Google Sheets show Hindi and Bengali correctly.
"""
import asyncio
import csv
import json
import pathlib
import random
import subprocess
import sys

from checker import advice, lang as langmod, taxonomy
from checker.pipeline import ASKED, CLAIMED, THREAT, CheckInput, run_check
from eval.run_eval import CachingProvider, to_input

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "review"
DATA = ROOT / "eval" / "data"
MODELS = ("gemini-3.5-flash-lite", "gemini-3.1-flash-lite")   # cached answers, newest first
PER_LANG = {"scam": 14, "unsure": 9, "no_signs": 7}


class _Stub:
    name = "gemini"

    def __init__(self, model):
        self.model = model


def load(name):
    return [json.loads(line) for line in open(DATA / f"{name}.jsonl", encoding="utf-8")]


def write_csv(name, header, rows):
    OUT.mkdir(exist_ok=True)
    with open(OUT / name, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  review/{name}: {len(rows)} rows")


def describe(row) -> str:
    """The message as a reader would see it; phone-call rows as a short description."""
    if row["kind"] != "call":
        return row["text"]
    c = row["call"]
    asked = ", ".join(ASKED.get(a, a) for a in c.get("asked") or []) or "nothing"
    return (f"[Phone call] Caller claimed to be: {CLAIMED.get(c.get('claimed'), '?')}. Asked to: {asked}. "
            f"Threat: {THREAT.get(c.get('threat'), '?')}. Video call or secrecy: {'yes' if c.get('video_or_secret') else 'no'}. "
            f"In their words: {c.get('details', '')}")


async def cards_for(rows):
    """Card for each row from cached answers, trying each cached model in turn."""
    out = {}
    for model in MODELS:
        prov = CachingProvider(_Stub(model), offline=True)
        for r in rows:
            if r["id"] in out:
                continue
            prov.reset()
            card, trace = await run_check(to_input(r), prov)
            if not trace.errors and trace.samples:
                out[r["id"]] = (card, model)
    return out


def explanation_text(card) -> str:
    parts = [card["summary"]]
    parts += [f"• {f['why']}" + (f"  (\"{f['quote']}\")" if f["quote"] else "") for f in card["red_flags"]]
    parts += [f"✓ {g}" for g in card["genuine_signs"]]
    return "\n".join(parts)


def explanation_sheets(rows):
    cards = asyncio.run(cards_for(rows))
    for lang in ("hi", "bn"):
        picked = []
        for verdict, n in PER_LANG.items():
            pool = [r for r in rows if r["id"] in cards and langmod.base(r["lang"]) == lang
                    and cards[r["id"]][0]["verdict"] == verdict and cards[r["id"]][0]["lang"] == lang]
            step = max(1, len(pool) // n) if pool else 1
            picked += pool[::step][:n]
        picked.sort(key=lambda r: r["id"])
        write_csv(f"explanations_{lang}.csv",
                  ["id", "message (what the person pasted)", "verdict shown", "explanation shown (written by the model)",
                   "meaning correct? (yes / no)", "reads naturally? (1-5)", "better wording (if any)", "notes"],
                  [[r["id"], describe(r), cards[r["id"]][0]["verdict_label"], explanation_text(cards[r["id"]][0]), "", "", "", ""]
                   for r in picked])


def ui_rows():
    rows = []

    def add(where, key, d):
        rows.append([where, key, d.get("en", ""), d.get("hi", ""), "", "", d.get("bn", ""), "", ""])

    for v in taxonomy.VERDICTS:
        add("verdict label", v, taxonomy.VERDICT_LABELS[v])
        add("headline", v, taxonomy.HEADLINES[v])
    for t in taxonomy.SCAM_TYPES:
        add("scam type", t, taxonomy.TYPE_LABELS[t])
    for v, by_lang in advice.NEXT_STEPS.items():
        for i in range(len(by_lang["en"])):
            add("next step", f"{v} {i + 1}", {k: by_lang[k][i] for k in by_lang})
    for t, d in advice.VERIFY.items():
        add("how to check", t, d)
    for i in range(len(advice.URGENT_STEPS["en"])):
        add("already paid", str(i + 1), {k: advice.URGENT_STEPS[k][i] for k in advice.URGENT_STEPS})
    for code, d in advice.FLAG_WHY.items():
        add("red flag", code, d)
    for name in ("DISCLAIMER", "TOO_SHORT", "NO_ASK", "RULES_ONLY", "SCREENSHOT_NOTE"):
        add("card note", name.lower(), getattr(advice, name))
    try:   # interface text lives in web/i18n.js
        js = "global.window={};require(process.argv[1]);process.stdout.write(JSON.stringify(window.I18N))"
        i18n = json.loads(subprocess.run(["node", "-e", js, str(ROOT / "web" / "i18n.js")], capture_output=True,
                                         text=True, encoding="utf-8", check=True).stdout)

        def walk(prefix, en, hi, bn):
            for k, v in en.items():
                if isinstance(v, dict):
                    walk(f"{prefix}{k}.", v, hi.get(k, {}), bn.get(k, {}))
                elif isinstance(v, str):
                    add("interface", prefix + k, {"en": v, "hi": hi.get(k, ""), "bn": bn.get(k, "")})
        walk("", i18n["en"], i18n.get("hi", {}), i18n.get("bn", {}))
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"  (interface text skipped: needs Node.js to read web/i18n.js: {e})", file=sys.stderr)
    return rows


def labelling_sheet():
    rng = random.Random(7)
    pool = {"scam": [], "genuine": [], "ambiguous": []}
    for name in ("golden", "holdout", "holdout2"):
        for r in load(name):
            pool[r["label"]].append(r)
    picked = [r for label in pool for r in rng.sample(pool[label], 20)]
    rng.shuffle(picked)
    write_csv("labelling_sheet.csv",
              ["item", "message", "your label (scam / genuine / ambiguous)", "scam type, if scam", "notes"],
              [[f"L{i:02d}", describe(r), "", "", ""] for i, r in enumerate(picked, 1)])
    write_csv("labelling_key.csv", ["item", "dataset id"], [[f"L{i:02d}", r["id"]] for i, r in enumerate(picked, 1)])


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    rows = load("golden") + load("holdout")
    explanation_sheets(rows)
    write_csv("ui_text.csv",
              ["where", "key", "English", "Hindi", "Hindi ok? (yes / no)", "Hindi fix", "Bengali", "Bengali ok? (yes / no)", "Bengali fix"],
              ui_rows())
    labelling_sheet()
    write_csv("real_messages_template.csv",
              ["message (paste exactly as received)", "received via (SMS / WhatsApp / email / call)",
               "your label (scam / genuine / ambiguous / not sure)", "notes"],
              [])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
