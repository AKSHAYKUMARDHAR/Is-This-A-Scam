"""Compare a second person's labels with the dataset's labels.

    python -m eval.agreement review/labelling_sheet.csv

Reads the filled sheet (item, message, label, scam type, notes) and review/labelling_key.csv, then
prints raw agreement, Cohen's kappa over the three labels, the confusion table, scam-type agreement
on rows both people call a scam, and every disagreement. Rows left blank are skipped.

Reading kappa: above 0.8 is strong agreement, 0.6 to 0.8 substantial, below 0.6 means the labels
(and so the eval numbers built on them) depend on who labelled.
"""
import argparse
import collections
import csv
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABELS = ("scam", "genuine", "ambiguous")
ALIASES = {"s": "scam", "fraud": "scam", "g": "genuine", "real": "genuine", "safe": "genuine", "a": "ambiguous",
           "unsure": "ambiguous", "can't tell": "ambiguous", "cant tell": "ambiguous", "not sure": "ambiguous"}


def norm_label(value: str) -> str | None:
    v = (value or "").strip().lower()
    v = ALIASES.get(v, v)
    return v if v in LABELS else None


def kappa(pairs) -> float | None:
    n = len(pairs)
    if not n:
        return None
    p_o = sum(a == b for a, b in pairs) / n
    ca, cb = collections.Counter(a for a, _ in pairs), collections.Counter(b for _, b in pairs)
    p_e = sum(ca[label] * cb[label] for label in LABELS) / (n * n)
    return 1.0 if p_e == 1 else (p_o - p_e) / (1 - p_e)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sheet")
    ap.add_argument("--key", default=str(ROOT / "review" / "labelling_key.csv"))
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    key = {row["item"]: row["dataset id"] for row in csv.DictReader(open(args.key, encoding="utf-8-sig"))}
    dataset = {}
    for path in sorted((ROOT / "eval" / "data").glob("*.jsonl")):
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            dataset[r["id"]] = r

    pairs, types, disagreements, bad = [], [], [], []
    with open(args.sheet, encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if not row or not row[0].strip():
                continue
            item, message, label = row[0].strip(), row[1], row[2] if len(row) > 2 else ""
            if not label.strip():
                continue
            theirs = norm_label(label)
            if theirs is None:
                bad.append((item, label))
                continue
            ref = dataset[key[item]]
            pairs.append((ref["label"], theirs))
            if ref["label"] == theirs == "scam" and len(row) > 3 and row[3].strip():
                types.append(row[3].strip().lower() in [ref.get("scam_type")] + (ref.get("alt_types") or []))
            if ref["label"] != theirs:
                disagreements.append((item, key[item], ref["label"], theirs, message[:120].replace("\n", " ")))

    if bad:
        print(f"Unrecognised labels (use scam / genuine / ambiguous): {bad}")
    if not pairs:
        print("No labelled rows yet.")
        return 1
    agree = sum(a == b for a, b in pairs)
    print(f"{len(pairs)} rows labelled; agreement {agree}/{len(pairs)} = {100 * agree / len(pairs):.1f}%; "
          f"Cohen's kappa {kappa(pairs):.2f}")
    print("\nrows: dataset label, columns: second labeller")
    print(f"{'':>10} " + " ".join(f"{label:>10}" for label in LABELS))
    table = collections.Counter(pairs)
    for a in LABELS:
        print(f"{a:>10} " + " ".join(f"{table[(a, b)]:>10}" for b in LABELS))
    if types:
        print(f"\nscam type agrees on {sum(types)}/{len(types)} rows both call a scam")
    if disagreements:
        print("\nDisagreements (item, dataset id, dataset label, second label, message):")
        for d in disagreements:
            print("  ", d)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
