"""Tools around the eval: agreement between labellers, and masking of collected real messages."""
import csv
import json

from checker import rules
from eval import agreement, ingest_real


def test_kappa():
    assert agreement.kappa([("scam", "scam"), ("genuine", "genuine"), ("ambiguous", "ambiguous")]) == 1.0
    assert agreement.kappa([("scam", "genuine"), ("genuine", "scam")]) < 0
    assert agreement.norm_label("Can't tell") == "ambiguous" and agreement.norm_label("maybe") is None


def test_ingest_masks_numbers_and_keeps_evidence(tmp_path):
    src = tmp_path / "in.csv"
    with open(src, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["message", "via", "label", "notes"])
        w.writerow(["Your a/c is blocked, call 9876543210 or pay at kyc-help.top to fix@ybl", "SMS", "scam", ""])
        w.writerow(["কাল দেখা হবে", "WhatsApp", "", ""])
    out = tmp_path / "real.jsonl"
    assert ingest_real.main([str(src), "--out", str(out)]) == 0
    rows = [json.loads(line) for line in open(out, encoding="utf-8")]
    assert "9876543210" not in rows[0]["text"] and "[PHONE]" in rows[0]["text"]
    assert "kyc-help.top" in rows[0]["text"] and "fix@ybl" in rows[0]["text"]
    assert [r["label"] for r in rows] == ["scam", "unlabelled"]
    # a masked number still counts as "call a number given in the message"
    assert "call_number" in rules.scan(rows[0]["text"]).codes("asks")
