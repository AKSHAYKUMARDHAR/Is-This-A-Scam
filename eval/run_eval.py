"""Evaluate the checker on a labelled set, through the same code path as production.

    python -m eval.run_eval eval/data/golden.jsonl                # run (model answers are cached)
    python -m eval.run_eval eval/data/golden.jsonl --sweep        # threshold sweep, no new calls
    python -m eval.run_eval eval/data/holdout.jsonl --gate        # release gate (PRD) on the held-out set
    python -m eval.run_eval eval/data/injection.jsonl             # injection suite

Versions, all from one set of cached model answers:
    A  rules only (a hard flag is "Likely scam"; everything else "Can't tell")
    B  rules + one model run
    C  rules + three-run self-consistency (production)

Every model answer is cached in eval/cache/ keyed by model, prompt version, the exact prompt and
the call index, so re-runs and sweeps cost nothing and a run interrupted by the free tier's daily
quota resumes where it stopped. Each run appends a summary line to eval/results/runs.jsonl.
"""
import argparse
import asyncio
import collections
import datetime as dt
import hashlib
import json
import pathlib
import sys

from checker import config, lang as langmod, policy, rules
from checker.llm import LLMError, Provider, QuotaExhausted, get_provider
from checker.pipeline import CheckInput, run_check
from checker.prompts import PROMPT_VERSION, SCHEMA, SYSTEM

ROOT = pathlib.Path(__file__).resolve().parent
CACHE_DIR = ROOT / "cache"
RESULTS = ROOT / "results"
PROMPT_HASH = hashlib.sha1((SYSTEM + json.dumps(SCHEMA, sort_keys=True)).encode()).hexdigest()[:8]


class CachingProvider(Provider):
    """Wraps a real provider; the n-th call with the same prompt returns the n-th cached answer."""

    def __init__(self, inner: Provider, offline: bool = False):
        self.inner, self.name, self.model, self.offline = inner, inner.name, inner.model, offline
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = CACHE_DIR / f"{inner.model}__{PROMPT_VERSION}-{PROMPT_HASH}.jsonl"
        self.cache: dict[tuple[str, int], dict] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                rec = json.loads(line)
                self.cache[(rec["key"], rec["idx"])] = rec
        self.counters: collections.Counter = collections.Counter()
        self.new_calls = 0
        self.lock = asyncio.Lock()

    def reset(self):
        self.counters.clear()

    async def classify(self, user: str):
        key = hashlib.sha1(user.encode()).hexdigest()[:16]
        async with self.lock:
            idx = self.counters[key]
            self.counters[key] += 1
        if (key, idx) in self.cache:
            rec = self.cache[(key, idx)]
            return rec["out"], rec["usage"]
        if self.offline:
            raise LLMError("not cached (offline)")
        out, usage = await self.inner.classify(user)
        rec = {"key": key, "idx": idx, "out": out, "usage": usage, "at": dt.datetime.now().isoformat(timespec="seconds")}
        async with self.lock:
            self.cache[(key, idx)] = rec
            self.new_calls += 1
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return out, usage


def to_input(row: dict) -> CheckInput:
    if row["kind"] == "call":
        return CheckInput(kind="call", call=row["call"])
    return CheckInput(kind="text", text=row["text"])


def raw_text(row: dict) -> str:
    return (row.get("call") or {}).get("details", "") if row["kind"] == "call" else row["text"]


async def run_version(rows, provider, samples, concurrency=4):
    """Run every row through run_check; returns {id: (card, trace)}. Stops cleanly on a daily quota."""
    sem = asyncio.Semaphore(concurrency)
    results, stop = {}, asyncio.Event()

    async def one(row):
        if stop.is_set():
            return
        async with sem:
            if stop.is_set():
                return
            try:
                results[row["id"]] = await run_check(to_input(row), provider, samples=samples)
            except QuotaExhausted as e:
                print(f"\n  stopped: {e}", file=sys.stderr)
                stop.set()

    done = 0
    tasks = [asyncio.create_task(one(r)) for r in rows]
    for t in asyncio.as_completed(tasks):
        await t
        done += 1
        if done % 20 == 0:
            print(f"  {done}/{len(rows)}", file=sys.stderr, flush=True)
    return results, stop.is_set()


def type_ok(row, scam_type) -> bool:
    return scam_type in [row.get("scam_type")] + (row.get("alt_types") or [])


def metrics(rows, verdicts: dict) -> dict:
    """verdicts: {id: (verdict, scam_type)}. Rates are over rows that have a verdict."""
    by = collections.defaultdict(list)
    for r in rows:
        if r["id"] in verdicts:
            by[r["label"]].append((r, *verdicts[r["id"]]))
    scam, gen, amb = by["scam"], by["genuine"], by["ambiguous"]
    n = len(scam) + len(gen) + len(amb)

    def rate(items, pred):
        return round(100 * sum(1 for x in items if pred(x)) / len(items), 1) if items else None

    flagged = [x for x in scam if x[1] == "scam"]
    fa_by_lang = collections.Counter(langmod.base(r["lang"]) for r, v, _ in gen if v == "scam")
    return {
        "n": n,
        "scam_n": len(scam), "genuine_n": len(gen), "ambiguous_n": len(amb),
        "false_alarms": sum(1 for _, v, _ in gen if v == "scam"),
        "false_alarm_rate": rate(gen, lambda x: x[1] == "scam"),
        "scams_cleared": sum(1 for _, v, _ in scam if v == "no_signs"),
        "scams_cleared_rate": rate(scam, lambda x: x[1] == "no_signs"),
        "scam_catch_rate": rate(scam, lambda x: x[1] == "scam"),
        "genuine_cleared_rate": rate(gen, lambda x: x[1] == "no_signs"),
        "ambiguous_cant_tell_rate": rate(amb, lambda x: x[1] == "unsure"),
        "cant_tell_rate": round(100 * sum(1 for items in (scam, gen, amb) for x in items if x[1] == "unsure") / n, 1) if n else None,
        "type_accuracy": rate(flagged, lambda x: type_ok(x[0], x[2])),
        "false_alarms_by_lang": dict(fa_by_lang),
    }


GATE = [
    ("False alarms <= 2% of genuine", lambda m: m["false_alarm_rate"] is not None and m["false_alarm_rate"] <= 2.0),
    ("Scams cleared <= 5% of scams", lambda m: m["scams_cleared_rate"] is not None and m["scams_cleared_rate"] <= 5.0),
    ("Scam type correct >= 85% of flagged scams", lambda m: m["type_accuracy"] is not None and m["type_accuracy"] >= 85.0),
    ("Ambiguous messages get can't tell >= 70%", lambda m: m["ambiguous_cant_tell_rate"] is not None and m["ambiguous_cant_tell_rate"] >= 70.0),
    ("No language has more than 2 false alarms", lambda m: all(v <= 2 for v in m["false_alarms_by_lang"].values())),
]


def sweep(rows, traces):
    """Re-decide version C at other thresholds from the cached samples (no model calls)."""
    print("\nThreshold sweep, version C (rows decided by a hard flag are unaffected)")
    print(f"{'scam_t':>7} {'gen_t':>6} | {'false_al%':>9} {'cleared%':>8} {'caught%':>8} {'gen_clr%':>8} {'amb_ct%':>8} {'cant%':>6}")
    for t_s in (0.5, 0.6, 0.7, 0.8, 0.9):
        for t_g in (0.6, 0.7, 0.8, 0.85, 0.9, 0.95):
            verdicts = {}
            for r in rows:
                if r["id"] not in traces:
                    continue
                res = rules.scan(raw_text(r), r.get("call"))
                card, trace = traces[r["id"]]
                ok = r["kind"] == "call" or len([c for c in raw_text(r) if c.isalnum()]) >= 12
                d = policy.decide(res, [] if res.hard else trace.samples, input_ok=ok, scam_threshold=t_s, genuine_threshold=t_g)
                verdicts[r["id"]] = (d.verdict, card["scam_type"])
            m = metrics(rows, verdicts)
            print(f"{t_s:7.2f} {t_g:6.2f} | {m['false_alarm_rate']!s:>9} {m['scams_cleared_rate']!s:>8} {m['scam_catch_rate']!s:>8} "
                  f"{m['genuine_cleared_rate']!s:>8} {m['ambiguous_cant_tell_rate']!s:>8} {m['cant_tell_rate']!s:>6}")


def third_run_effect(traces) -> dict:
    """How often the third sample changed the outcome after the first two agreed."""
    agreed = flipped = 0
    for card, trace in traces.values():
        labels = [s["label"] for s in trace.samples]
        if len(labels) >= 3 and labels[0] == labels[1]:
            agreed += 1
            flipped += labels[2] != labels[0]
    return {"first_two_agreed": agreed, "third_disagreed": flipped}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--gate", action="store_true", help="print the PRD release gate for version C")
    ap.add_argument("--offline", action="store_true", help="use cached model answers only")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--ids", help="comma-separated ids or ranges, e.g. G166-G200,G089")
    ap.add_argument("--note", default="")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    rows = [json.loads(line) for line in open(args.path, encoding="utf-8")]
    if args.ids:
        wanted = set()
        for part in args.ids.split(","):
            if "-" in part:
                lo, hi = part.split("-")
                wanted |= {f"{lo[0]}{n:03d}" for n in range(int(lo[1:]), int(hi[1:]) + 1)}
            else:
                wanted.add(part.strip())
        rows = [r for r in rows if r["id"] in wanted]
    if args.limit:
        rows = rows[: args.limit]
    set_name = pathlib.Path(args.path).stem
    inner = get_provider()
    if inner is None:
        print("No model credentials: only version A (rules only) can run. Set GEMINI_API_KEY or ANTHROPIC_API_KEY in .env.")
    provider = CachingProvider(inner, offline=args.offline) if inner else None

    async def go():
        out = {}
        if provider:
            print(f"version C on {set_name} ({len(rows)} rows, {provider.model}, prompt {PROMPT_VERSION}-{PROMPT_HASH})", file=sys.stderr)
            provider.reset()
            out["C"] = await run_version(rows, provider, samples=config.SAMPLES)
            provider.reset()
            out["B"] = await run_version(rows, provider, samples=1)
        out["A"] = await run_version(rows, None, samples=0)
        return out

    runs = asyncio.run(go())
    stopped = any(s for _, s in runs.values())
    summary = {}
    print(f"\n{set_name}: {len(rows)} rows" + ("  (INCOMPLETE: stopped on quota, re-run to resume)" if stopped else ""))
    header = f"{'ver':3} {'n':>4} | {'false al.':>10} {'cleared':>8} {'caught%':>8} {'genuine clr%':>12} {'amb ct%':>8} {'cant%':>6} {'type%':>6}"
    print(header)
    for ver in ("A", "B", "C"):
        if ver not in runs:
            continue
        results, _ = runs[ver]
        m = metrics(rows, {i: (c["verdict"], c["scam_type"]) for i, (c, _) in results.items()})
        calls = sum(t.calls for _, t in results.values())
        errors = sum(len(t.errors) for _, t in results.values())
        tokens = (sum(t.input_tokens for _, t in results.values()), sum(t.output_tokens for _, t in results.values()))
        m.update({"model_calls": calls, "model_errors": errors, "input_tokens": tokens[0], "output_tokens": tokens[1]})
        summary[ver] = m
        fa = f"{m['false_alarms']}/{m['genuine_n']}" if m["genuine_n"] else "-"
        cl = f"{m['scams_cleared']}/{m['scam_n']}" if m["scam_n"] else "-"
        print(f"{ver:3} {m['n']:>4} | {fa:>10} {cl:>8} {m['scam_catch_rate']!s:>8} {m['genuine_cleared_rate']!s:>12} "
              f"{m['ambiguous_cant_tell_rate']!s:>8} {m['cant_tell_rate']!s:>6} {m['type_accuracy']!s:>6}")
    if "C" in runs:
        c = summary["C"]
        print(f"\nversion C: {c['model_calls']} model calls ({c['model_calls'] / max(c['n'], 1):.2f} per check), "
              f"{c['model_errors']} errors, {c['input_tokens']:,} input + {c['output_tokens']:,} output tokens; "
              f"false alarms by language {c['false_alarms_by_lang']}")
        print(f"third run: {third_run_effect(runs['C'][0])}")
        reasons = collections.Counter(card["reason"] for card, _ in runs["C"][0].values())
        print(f"verdict reasons: {dict(reasons)}")
        if set_name.startswith("injection"):
            flips = [i for i, (card, _) in runs["C"][0].items() if card["verdict"] == "no_signs"]
            print(f"injection: {len(flips)} verdict flips to 'No scam signs found' {flips}; "
                  f"caught as scam {sum(1 for card, _ in runs['C'][0].values() if card['verdict'] == 'scam')}/{len(runs['C'][0])}")
            summary["C"]["injection_flips"] = flips
        if args.gate:
            print("\nRelease gate (PRD), version C:")
            for name, check in GATE:
                print(f"  [{'PASS' if check(c) else 'FAIL'}] {name}")
        if args.sweep:
            sweep(rows, runs["C"][0])

    # wrong verdicts, for error analysis
    if "C" in runs:
        wrong = []
        for r in rows:
            if r["id"] not in runs["C"][0]:
                continue
            card, trace = runs["C"][0][r["id"]]
            bad = (r["label"] == "genuine" and card["verdict"] == "scam") or (r["label"] == "scam" and card["verdict"] == "no_signs")
            if bad or (r["label"] == "scam" and card["verdict"] == "scam" and not type_ok(r, card["scam_type"])):
                wrong.append((r["id"], r["label"], r.get("scam_type"), card["verdict"], card["scam_type"], card["reason"],
                              [(s["label"], round(s["confidence"], 2)) for s in trace.samples]))
        if wrong:
            print("\nErrors (false alarm, scam cleared, or wrong type):")
            for w in wrong:
                print("  ", w)

    RESULTS.mkdir(exist_ok=True)
    with (RESULTS / "runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "at": dt.datetime.now().isoformat(timespec="seconds"), "set": set_name, "rows": len(rows), "complete": not stopped,
            "model": getattr(inner, "model", None), "prompt": f"{PROMPT_VERSION}-{PROMPT_HASH}", "samples": config.SAMPLES,
            "scam_threshold": config.SCAM_THRESHOLD, "genuine_threshold": config.GENUINE_THRESHOLD,
            "dataset_sha256": hashlib.sha256(pathlib.Path(args.path).read_bytes()).hexdigest()[:16],
            "note": args.note, "versions": summary,
        }, ensure_ascii=False) + "\n")
    if "C" in runs:
        with (RESULTS / f"decisions_{set_name}.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                if r["id"] in runs["C"][0]:
                    card, trace = runs["C"][0][r["id"]]
                    f.write(json.dumps({"id": r["id"], "label": r["label"], "lang": r["lang"], "verdict": card["verdict"],
                                        "scam_type": card["scam_type"], "reason": card["reason"], "hard_flags": card["hard_flags"],
                                        "samples": [(s["label"], s["confidence"], s.get("scam_type")) for s in trace.samples]},
                                       ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
