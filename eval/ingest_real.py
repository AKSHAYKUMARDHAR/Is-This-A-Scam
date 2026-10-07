"""Turn collected real messages into a masked eval set.

    python -m eval.ingest_real path/to/real_messages.csv        # writes data/real/real.jsonl

Input: the columns of review/real_messages_template.csv (message, received via, your label, notes).
Every message is masked with the same code the app uses before a model call (card, Aadhaar,
account, phone, OTP and PAN numbers); links, amounts and UPI IDs are kept because they are evidence.
Names of people and addresses are NOT masked: read the output and replace them with [name] or
[address] by hand before sharing it or committing it anywhere.

The output goes to data/real/, which git ignores. Then:

    python -m eval.run_eval data/real/real.jsonl --note "real messages, first batch"

Rows labelled "not sure" are kept as "ambiguous"; unlabelled rows are kept as "unlabelled" (they get
verdicts in eval/results/decisions_real.jsonl but are left out of the metrics).
"""
import argparse
import collections
import csv
import json
import pathlib
import sys

from checker import lang as langmod, masking
from eval.agreement import norm_label

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default=str(ROOT / "data" / "real" / "real.jsonl"))
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows, masked_total, labels = [], collections.Counter(), collections.Counter()
    with open(args.csv, encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        next(reader)
        for line in reader:
            if not line or not line[0].strip():
                continue
            text = line[0].strip()
            masked, counts = masking.mask(text)
            masked_total.update(counts)
            label = norm_label(line[2] if len(line) > 2 else "") or "unlabelled"
            labels[label] += 1
            rows.append({"id": f"R{len(rows) + 1:03d}", "lang": langmod.detect(masked), "kind": "text", "label": label,
                         "source": (line[1] if len(line) > 1 else "").strip().lower(),
                         "notes": (line[3] if len(line) > 3 else "").strip(), "text": masked})
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{len(rows)} messages -> {out}")
    print(f"labels: {dict(labels)}; languages: {dict(collections.Counter(r['lang'] for r in rows))}")
    print(f"masked: {dict(masked_total) or 'nothing'}")
    print("Now read the file and replace any names or addresses by hand before sharing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
