"""Tables per model: how well it triages the labeled findings.

  stats.py --items eval/items.jsonl --results results --models A B --out results/report.md
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

# Juliet splits many flows across functions: a sink, a source, or a caller
# that hands data to one. What decides the label may then be outside the context.
SPLIT_FLOW = re.compile(r"\w*(?:Sink|Source)\w*")


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pct(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


def wilson(k: int, n: int, z: float = 1.96) -> str:
    """95% Wilson score interval, in percent."""
    if not n:
        return "n/a"
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{100 * max(0.0, centre - half):.0f}-{100 * min(1.0, centre + half):.0f}%"


def self_contained(item: dict) -> bool:
    """True when the flagged function is neither a split-out sink or source
    nor a caller of one, so source and sink are both in the context."""
    if SPLIT_FLOW.search(item["function"]):
        return False
    lines = item["code_context"].splitlines()
    sig = re.compile(rf"^[A-Za-z_].*\b{re.escape(item['function'])}\s*\(")
    start = next((k for k, line in enumerate(lines) if sig.match(line)), 0)
    return not re.search(SPLIT_FLOW.pattern + r"\s*\(", "\n".join(lines[start:]))


def row(model: str, items: list[dict], res: dict[str, dict]) -> str:
    tp = [i for i in items if i["label"] == "TP"]
    fp = [i for i in items if i["label"] == "FP"]
    verdict = {i["id"]: (res.get(i["id"]) or {}).get("verdict") for i in items}
    kept = sum(verdict[i["id"]] == "TP" for i in tp)
    dismissed = sum(verdict[i["id"]] == "FP" for i in fp)
    # A missing or invalid answer counts as wrong on both sides.
    balanced = (f"{50 * (kept / len(tp) + dismissed / len(fp)):.1f}%"
                if tp and fp else "n/a")
    latency = sorted(r["latency_s"] for r in res.values() if r.get("latency_s"))
    median = f"{latency[len(latency) // 2]:.0f}s" if latency else "n/a"
    total = f"{sum(latency) / 60:.0f} min" if latency else "n/a"
    tokens = sorted(r["completion_tokens"] for r in res.values()
                    if r.get("completion_tokens") is not None)
    median_tokens = str(tokens[len(tokens) // 2]) if tokens else "n/a"
    costs = [r["cost_usd"] for r in res.values() if r.get("cost_usd") is not None]
    cost = f"${sum(costs):.2f}" if costs else "local"
    return (f"| {model} | {len(res)}/{len(items)} "
            f"| {pct(kept, len(tp))} | {pct(dismissed, len(fp))} | {balanced} "
            f"| {pct(sum(v == 'UNCERTAIN' for v in verdict.values()), len(items))} "
            f"| {pct(sum(v is None for v in verdict.values()), len(items))} | {median} "
            f"| {total} | {median_tokens} | {cost} |")


def filter_row(model: str, items: list[dict], res: dict[str, dict]) -> str:
    """Only an FP verdict removes a finding; everything else goes to a human."""
    answered = [i for i in items if i["id"] in res]
    tp = [i for i in answered if i["label"] == "TP"]
    fp = [i for i in answered if i["label"] == "FP"]
    missed = sum(res[i["id"]].get("verdict") == "FP" for i in tp)
    dismissed = sum(res[i["id"]].get("verdict") == "FP" for i in fp)
    return (f"| {model} | {missed}/{len(tp)} ({wilson(missed, len(tp))}) "
            f"| {dismissed}/{len(fp)} ({wilson(dismissed, len(fp))}) "
            f"| {pct(len(answered) - missed - dismissed, len(answered))} |")


def heading(title: str, subset: list[dict]) -> str:
    return (f"## {title}: {len(subset)} findings, "
            f"{sum(i['label'] == 'TP' for i in subset)} real, "
            f"{sum(i['label'] == 'FP' for i in subset)} false positives")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--items", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    items = load(Path(args.items))
    runs = {m: {r["id"]: r for r in load(p)} for m in args.models
            if (p := Path(args.results) / f"{m}_primary.jsonl").exists()}
    juliet = [i for i in items if i["source"] == "juliet"]

    lines = [heading("Juliet (labels independent of every model)", juliet), "",
             ("| model | answered | real bugs kept | false positives dismissed "
              "| balanced accuracy | uncertain | no valid answer | median time "
              "| total time | median output tokens | API-equivalent cost |"),
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    ids = {i["id"] for i in juliet}
    for model, res in runs.items():
        lines.append(row(model, juliet, {k: v for k, v in res.items() if k in ids}))
    lines.append("")

    if all("stratum" in i for i in juliet):  # v2 items
        subsets = [("As a filter", juliet)]
    else:
        subsets = [("As a filter, all Juliet", juliet),
                   ("As a filter, source and sink both shown",
                    [i for i in juliet if self_contained(i)]),
                   ("As a filter, flow split across functions",
                    [i for i in juliet if not self_contained(i)])]
    for title, subset in subsets:
        lines += [heading(title, subset), "",
                  ("| model | real bugs auto-dismissed (95% CI) "
                   "| false positives auto-dismissed (95% CI) | sent to a human |"),
                  "|---|---|---|---|"]
        for model, res in runs.items():
            lines.append(filter_row(model, subset, res))
        lines.append("")

    strata = sorted({i["stratum"] for i in juliet if i.get("stratum", "tp") != "tp"})
    if strata:
        lines += ["## False positives dismissed, by kind", "",
                  ("`fp_paired`: the same sink as a real bug, made safe by its source "
                   "or a check. `fp_other`: other in-family lines in safe code. "
                   "`fp_offtarget`: a rule unrelated to the test case's weakness."), "",
                  "| model | " + " | ".join(
                      f"{s} (n={sum(i.get('stratum') == s for i in juliet)})"
                      for s in strata) + " |",
                  "|---|" + "---|" * len(strata)]
        for model, res in runs.items():
            cells = []
            for s in strata:
                sub = [i for i in juliet if i.get("stratum") == s and i["id"] in res]
                cells.append(pct(sum(res[i["id"]].get("verdict") == "FP" for i in sub),
                                 len(sub)))
            lines.append(f"| {model} | " + " | ".join(cells) + " |")
        lines.append("")

    thresholds = (0.0, 0.8, 0.9, 0.95)
    lines += ["## Auto-dismiss only above a confidence threshold", "",
              ("Real bugs lost / false positives removed, when an FP verdict removes "
               "a finding only if its confidence is at least the threshold. Picked on "
               "the test set itself, so optimistic."), "",
              "| model | " + " | ".join(f">= {t}" for t in thresholds) + " |",
              "|---|" + "---|" * len(thresholds)]
    for model, res in runs.items():
        cells = []
        for t in thresholds:
            gone = [i for i in juliet if (r := res.get(i["id"])) and r.get("verdict") == "FP"
                    and (r.get("confidence") or 0) >= t]
            lost = sum(i["label"] == "TP" for i in gone)
            cells.append(f"{lost} / {len(gone) - lost}")
        lines.append(f"| {model} | " + " | ".join(cells) + " |")
    lines.append("")
    Path(args.out).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
