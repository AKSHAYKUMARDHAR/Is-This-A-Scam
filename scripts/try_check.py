"""Run one check from the command line and print the card.

    python -m scripts.try_check "Your SBI KYC expires today, update at sbi-kyc.xyz"
    python -m scripts.try_check --lang hi --image screenshot.png
"""
import argparse
import asyncio
import json
import pathlib
import sys

from checker.llm import get_provider
from checker.pipeline import CheckInput, run_check


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?", default="")
    ap.add_argument("--lang", default="auto")
    ap.add_argument("--image")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    provider = get_provider()
    if args.image:
        path = pathlib.Path(args.image)
        mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
        inp = CheckInput(kind="image", image=path.read_bytes(), image_mime=mime, ui_lang=args.lang)
    else:
        inp = CheckInput(kind="text", text=args.text, ui_lang=args.lang)
    card, trace = asyncio.run(run_check(inp, provider))
    print(json.dumps(card, ensure_ascii=False, indent=2))
    print(f"provider={getattr(provider, 'name', None)} model={getattr(provider, 'model', None)} calls={trace.calls} "
          f"samples={[ (s['label'], round(s['confidence'], 2)) for s in trace.samples ]} errors={trace.errors}")


if __name__ == "__main__":
    main()
