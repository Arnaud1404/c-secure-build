"""Bag-of-tokens naive Bayes floor: what shallow cues alone score.

  baseline.py --train eval_v2/train.jsonl --test eval_v2/test.jsonl --out results_v2/nb-floor_primary.jsonl

Trained on a label-balanced sample of the train split (families disjoint
from test), on the scrubbed prompt code plus the rule id. A model that does
not beat this is not reading the code.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
from collections import Counter
from pathlib import Path

from run_eval import scrub

TOKEN = re.compile(r"[A-Za-z_]\w+|\S")


def tokens(item: dict) -> set[str]:
    return set(TOKEN.findall(scrub(item["code_context"]))) | {"RULE_" + item["rule_id"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    train = [json.loads(line) for line in Path(args.train).read_text().splitlines() if line]
    test = [json.loads(line) for line in Path(args.test).read_text().splitlines() if line]
    rng = random.Random(0)
    tp = [i for i in train if i["label"] == "TP"]
    fp = [i for i in train if i["label"] == "FP"]
    sample = tp + rng.sample(fp, min(len(fp), len(tp)))

    counts = {"TP": Counter(), "FP": Counter()}
    n = Counter()
    for item in sample:
        counts[item["label"]].update(tokens(item))
        n[item["label"]] += 1
    vocab = set(counts["TP"]) | set(counts["FP"])

    with Path(args.out).open("w") as fh:
        for item in test:
            toks = tokens(item) & vocab
            score = {lab: sum(math.log((counts[lab][t] + 1) / (n[lab] + 2)) for t in toks)
                     for lab in ("TP", "FP")}
            verdict = max(score, key=score.get)
            # Posterior of the chosen label, from the log-likelihood gap.
            gap = abs(score["TP"] - score["FP"])
            fh.write(json.dumps({
                "id": item["id"], "label": item["label"], "model": "nb-floor",
                "verdict": verdict, "confidence": round(1 / (1 + math.exp(-gap)), 4),
                "cwe": "", "reason": "", "schema_valid": True,
            }) + "\n")
    print(f"wrote {len(test)} verdicts to {args.out}")


if __name__ == "__main__":
    main()
