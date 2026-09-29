"""Build the v2 eval set: self-contained Juliet flows, line-level labels,
a family-level train/test split, and a context that does not give the label away.

  build_v2.py sample --juliet DIR --out WORK
  build_v2.py items  --work WORK --out EVAL_DIR

Differences from build_items.py (v1):
- Only flow variants 01-18, where source and sink sit in one function.
- Split by functional variant (the test case name without its flow number),
  so no test family has a near-copy in train.
- TP only when the flagged line is the statement under a FLAW or POTENTIAL
  FLAW comment in bad(). Other bad() lines are dropped, not guessed.
- An off-target stratum: findings whose rule CWE is outside the test case's
  family. Juliet test cases carry only the target flaw, apart from lines
  marked INCIDENTAL, which are dropped.
- The context is the file preamble plus the flagged function, renumbered
  from 1, with label-bearing names replaced by random per-item names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

from build_items import (
    JULIET_DIRS,
    SEED,
    TARGET_FAMILY,
    function_spans,
    juliet_label,
    sarif_findings,
)
from run_eval import COMMENT, LEAK_WORDS, NAME_WITH_LABEL, PREPROC_LABEL, STRING

FLOW = re.compile(r"_(0[1-9]|1[0-8])\.c$")
TEST_SHARE = 0.25
CONTEXT_CHAR_CAP = 24000
MAX_PER_FAMILY = 2
MAX_RULE_SHARE = 0.20
# Test set strata. The FP side is larger, as in real scanner output.
TEST_QUOTA = {"tp": 50, "fp_paired": 35, "fp_other": 15, "fp_offtarget": 20}

# An array declaration only sizes a buffer; the overflow is at the copy.
ARRAY_DECL = re.compile(r"^\s*(?:(?:const|unsigned|signed|static|struct)\s+)*\w+[\s*]+\w+\s*\[[^\]]*\]\s*(?:=[^;]*)?;")
# Flow variants 01-18 still hand data to a separate function in some
# families (the vprintf VaSink helpers, for instance). Those are not
# self-contained, whether the flagged function is the helper or the caller.
SPLIT = re.compile(r"\w*(?:Sink|Source|[Hh]elper)\w*")
MARKER = re.compile(r"/\*\s*(POTENTIAL FLAW|FLAW|FIX|INCIDENTAL)\b")
SYLLABLES = ["ka", "lo", "mi", "ne", "ru", "ta", "vo", "ze", "pi", "su", "de",
             "ho", "ja", "we", "ly", "no", "ri", "te", "qu", "ce"]


def family(path: Path) -> str:
    return FLOW.sub("", path.name)


def cmd_sample(args: argparse.Namespace) -> None:
    root = Path(args.juliet) / "C" / "testcases"
    out = Path(args.out) / "juliet"
    if out.exists():
        shutil.rmtree(out)
    split: dict[str, str] = {}
    for cwe, dirname in JULIET_DIRS.items():
        files = sorted(p for p in (root / dirname).rglob("*.c")
                       if "w32" not in p.name and FLOW.search(p.name))
        fams = sorted({family(p) for p in files})
        rng = random.Random(f"{SEED}-{cwe}")
        rng.shuffle(fams)
        n_test = max(1, round(len(fams) * TEST_SHARE))
        for i, fam in enumerate(fams):
            split[fam] = "test" if i < n_test else "train"
        dest = out / cwe
        dest.mkdir(parents=True)
        for p in files:
            shutil.copy2(p, dest / p.name)
        print(f"CWE-{cwe}: {len(files)} files, {len(fams)} families, {n_test} for test")
    (Path(args.out) / "split.json").write_text(json.dumps(split, indent=1, sort_keys=True))


def marker_above(lines: list[str], idx: int, lo: int) -> str | None:
    """The nearest marker governing line idx (0-based), if any. Juliet puts a
    marker above a region: the statements after it in the same block,
    including nested blocks. Walks up, skipping the insides of sibling
    blocks, and climbs to the enclosing block when the current one opens."""
    depth = 0
    for k in range(idx - 1, lo - 1, -1):
        code = COMMENT.sub("", lines[k]).strip()
        m = MARKER.search(lines[k])
        if m and not code and depth == 0:
            return m.group(1)
        depth = max(0, depth + code.count("}") - code.count("{"))
    return None


def neutral_name(rng: random.Random, used: set[str]) -> str:
    while True:
        name = "".join(rng.choice(SYLLABLES) for _ in range(3))
        if name not in used and not LEAK_WORDS.search(name):
            used.add(name)
            return name


def prompt_code(preamble: list[str], func: list[str], seed: str) -> tuple[str, int]:
    """Scrub comments, label strings and label-bearing names. Names get
    random replacements so their order says nothing about the label.
    Returns the code and the number of leading blank lines dropped."""
    code = "".join(preamble) + "\n" + "".join(func)
    close, open_ = code.find("*/"), code.find("/*")
    if close != -1 and (open_ == -1 or close < open_):
        code = "\n" * code[:close + 2].count("\n") + code[close + 2:]
    code = COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), code)
    code = PREPROC_LABEL.sub("", code)
    code = STRING.sub(lambda m: m.group(0) if not LEAK_WORDS.search(m.group(2))
                      else f'{m.group(1)}"{"x" * len(m.group(2))}"', code)
    rng = random.Random(seed)
    names: dict[str, str] = {}
    used: set[str] = set()
    code = NAME_WITH_LABEL.sub(
        lambda m: names.setdefault(m.group(0), neutral_name(rng, used)), code)
    lead = re.match(r"(?:[ \t]*\n)*", code).group(0)
    trimmed = lead.count("\n")
    code = code[len(lead):]
    if len(code) > CONTEXT_CHAR_CAP:
        code = code[:CONTEXT_CHAR_CAP] + "\n/* [truncated] */\n"
    return code, trimmed


def classify(label: str, in_family: bool, marker: str | None, line: str) -> str | None:
    if marker == "INCIDENTAL":
        return None
    if label == "TP" and ARRAY_DECL.match(line):
        return None
    if not in_family:
        # A flaw line flagged by an unrelated rule is neither clean FP nor TP.
        return None if marker in ("FLAW", "POTENTIAL FLAW") and label == "TP" \
            else "fp_offtarget"
    if label == "TP":
        return "tp" if marker in ("FLAW", "POTENTIAL FLAW") else None
    return "fp_paired" if marker in ("POTENTIAL FLAW", "FIX") else "fp_other"


def select(pool: list[dict], quota: int) -> list[dict]:
    """Round-robin over CWEs, then rules; at most MAX_PER_FAMILY items per
    family and MAX_RULE_SHARE of the stratum per rule."""
    rng = random.Random(SEED)
    groups: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for it in sorted(pool, key=lambda i: i["key"]):
        groups[it["cwe"]][it["rule_id"]].append(it)
    for by_rule in groups.values():
        for group in by_rule.values():
            rng.shuffle(group)
    cap = max(1, int(quota * MAX_RULE_SHARE))
    per_rule: Counter = Counter()
    per_family: Counter = Counter()
    turn: Counter = Counter()
    picked: list[dict] = []
    while len(picked) < quota:
        progress = False
        for cwe in sorted(groups):
            if len(picked) >= quota:
                break
            rules = [r for r in sorted(groups[cwe]) if groups[cwe][r] and per_rule[r] < cap]
            while rules:
                rule = rules[turn[cwe] % len(rules)]
                turn[cwe] += 1
                it = groups[cwe][rule].pop()
                if per_family[it["family"]] < MAX_PER_FAMILY:
                    picked.append(it)
                    per_rule[rule] += 1
                    per_family[it["family"]] += 1
                    progress = True
                    break
                rules = [r for r in rules if groups[cwe][r]]
        if not progress:
            break
    return picked


def cmd_items(args: argparse.Namespace) -> None:
    work = Path(args.work)
    split = json.loads((work / "split.json").read_text())
    pools: dict[str, dict[str, list[dict]]] = {"test": defaultdict(list),
                                               "train": defaultdict(list)}
    dropped: Counter = Counter()
    cache: dict[Path, tuple[list[str], list]] = {}
    seen: set[str] = set()

    for sarif in sorted((work / "sarif").glob("*.sarif")):
        for f in sarif_findings(sarif):
            path = work / f["uri"]
            if not path.exists():
                dropped["file missing"] += 1
                continue
            if path not in cache:
                text = path.read_text(errors="replace")
                cache[path] = (text.splitlines(keepends=True), function_spans(text))
            lines, spans = cache[path]
            func = next((s for s in spans if s.start <= f["start_line"] <= s.end), None)
            if func is None:
                dropped["outside any function"] += 1
                continue
            label = juliet_label(func.name)
            if label is None:
                dropped["function neither bad nor good"] += 1
                continue
            body = lines[func.start - 1:func.end]
            if SPLIT.fullmatch(func.name) or re.search(SPLIT.pattern + r"\s*\(",
                                                        "".join(body[1:])):
                dropped["split flow (sink, source or helper)"] += 1
                continue
            cwe = path.parent.name
            in_family = bool(set(f["rule_cwes"]) & TARGET_FAMILY[cwe])
            marker = marker_above(lines, f["start_line"] - 1, func.start - 1)
            stratum = classify(label, in_family, marker, lines[f["start_line"] - 1])
            if stratum is None:
                dropped[f"ambiguous ({label}, marker {marker}, in family {in_family})"] += 1
                continue
            key = f"{path.name}:{f['start_line']}:{f['rule_id']}"
            if key in seen:
                dropped["duplicate"] += 1
                continue
            seen.add(key)
            labelled = [s for s in spans if juliet_label(s.name) is not None]
            first = min(s.start for s in labelled)
            preamble = lines[:first - 1]
            code, trimmed = prompt_code(preamble, body, key)
            offset = len(preamble) + 1 - trimmed  # +1: the blank separator line
            if LEAK_WORDS.search(f["message"]):
                dropped["label word in the analyzer message"] += 1
                continue
            fam = family(path)
            pools[split[fam]][stratum].append({
                "key": key,
                "source": "juliet",
                "family": fam,
                "stratum": stratum,
                "tool": f["tool"],
                "rule_id": f["rule_id"],
                "cwe": cwe,
                "message": f["message"],
                "file": path.relative_to(work).as_posix(),
                "start_line": offset + f["start_line"] - func.start + 1,
                "end_line": offset + f["end_line"] - func.start + 1,
                "orig_line": f["start_line"],
                "function": func.name,
                "code_context": code,
                "context_start_line": 1,
                "label": "TP" if stratum == "tp" else "FP",
                "label_reason": f"Juliet v2: {stratum} in {func.name}, marker {marker}",
                "needs_human_review": False,
            })

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    test: list[dict] = []
    for stratum, quota in TEST_QUOTA.items():
        picked = select(pools["test"][stratum], quota)
        if len(picked) < quota:
            print(f"WARN: {stratum}: only {len(picked)} of {quota}", file=sys.stderr)
        test += picked
    for i, it in enumerate(test, 1):
        it["id"] = f"t2-{i:03d}"
    train = [it for s in sorted(pools["train"]) for it in pools["train"][s]]
    for it in train:
        it["id"] = "tr-" + hashlib.sha256(it["key"].encode()).hexdigest()[:10]
    for name, rows in (("test.jsonl", test), ("train.jsonl", train)):
        with (out / name).open("w") as fh:
            for it in rows:
                fh.write(json.dumps(it) + "\n")
    print(f"dropped: {dict(dropped)}")
    for name, pool in pools.items():
        print(f"{name} pool:", {s: len(v) for s, v in sorted(pool.items())})
    print(f"test: {len(test)}", dict(Counter(i["stratum"] for i in test)),
          "cwe", dict(Counter(i["cwe"] for i in test)))
    print("test rules:", dict(Counter(i["rule_id"] for i in test).most_common()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--juliet", required=True)
    s.add_argument("--out", required=True)
    i = sub.add_parser("items")
    i.add_argument("--work", required=True)
    i.add_argument("--out", required=True)
    args = parser.parse_args()
    {"sample": cmd_sample, "items": cmd_items}[args.cmd](args)


if __name__ == "__main__":
    main()
