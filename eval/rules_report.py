"""Rules-only report for a test set: which hard and strong flags fire on which labels.

    python -m eval.rules_report eval/data/golden.jsonl [--verbose]

Hard flags on genuine messages are the number that matters: each one is a false alarm that no
model can overrule. Scams with no hard flag, no strong signal and no risky ask can at best get
"Can't tell" (policy rule 8), so those are listed too.
"""
import argparse
import collections
import json
import sys

from checker import rules


def text_of(row: dict) -> str:
    return (row.get("call") or {}).get("details", "") if row["kind"] == "call" else row["text"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--verbose", action="store_true", help="list every non-scam row with a flag and every scam without a hard flag")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    rows = [json.loads(line) for line in open(args.path, encoding="utf-8")]
    tiers = collections.Counter()
    false_hard, capped = [], []
    for row in rows:
        res = rules.scan(text_of(row), row.get("call"))
        tier = "hard" if res.hard else "strong" if res.strong else "none"
        tiers[(row["label"], tier)] += 1
        if row["label"] != "scam" and res.hard:
            false_hard.append((row["id"], row["label"], [(f.code, f.quote) for f in res.hard]))
        if row["label"] == "scam" and not (res.hard or res.strong or res.risky_ask()):
            capped.append(row["id"])
        if args.verbose:
            if row["label"] != "scam" and (res.hard or res.strong):
                print(f"  {row['id']} {row['label']}: hard={res.codes('hard')} strong={[(f.code, f.quote) for f in res.strong]}")
            if row["label"] == "scam" and not res.hard:
                print(f"  {row['id']} scam/{row.get('scam_type')} no hard flag, strong={res.codes('strong')} | {text_of(row)[:80]}")

    print(f"\n{args.path}: {len(rows)} rows")
    for label in ("scam", "genuine", "ambiguous"):
        n = sum(v for (lab, _), v in tiers.items() if lab == label)
        if n:
            parts = ", ".join(f"{t} {tiers[(label, t)]}" for t in ("hard", "strong", "none"))
            print(f"  {label:9s} {n:3d}: {parts}")
    print(f"  scams that can at best get \"Can't tell\" (no hard flag, strong signal or risky ask): {len(capped)} {capped}")
    print(f"  hard flags on non-scam rows: {len(false_hard)}")
    for item in false_hard:
        print("   ", item)
    return 1 if false_hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
