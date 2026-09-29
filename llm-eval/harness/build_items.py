"""Build the labeled eval set from Juliet C 1.3 and this repo's own findings.

  build_items.py sample --juliet DIR --out WORK
  build_items.py items  --work WORK --proposals FILE --out EVAL_DIR
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

SEED = 20260927
REPO = Path(__file__).resolve().parents[2]

JULIET_DIRS = {
    "121": "CWE121_Stack_Based_Buffer_Overflow",
    "122": "CWE122_Heap_Based_Buffer_Overflow",
    "134": "CWE134_Uncontrolled_Format_String",
    "190": "CWE190_Integer_Overflow",
    "415": "CWE415_Double_Free",
    "416": "CWE416_Use_After_Free",
    "78": "CWE78_OS_Command_Injection",
}

# Rule CWEs that count as "the target type" for each Juliet category
# (User Guide v1.2, section 8). Anything else is excluded, not labeled.
TARGET_FAMILY = {
    "121": {"119", "120", "121", "122", "125", "126", "127", "131", "170",
            "787", "788", "805", "806"},
    "190": {"190", "128", "680"},
    "134": {"134"},
    "415": {"415"},
    "416": {"416", "825"},
    "78": {"78", "77", "88"},
}
TARGET_FAMILY["122"] = TARGET_FAMILY["121"]

# User Guide v1.2, sections 4.1.1 to 4.1.2.
BAD_FUNCS = [
    r"^(CWE.*_)?bad$",
    r"^(CWE.+_)?(helperBad|badVaSink[BG]?)$",
    r"^(CWE.+_)?badSource(_[a-z])?$",
    r"^(CWE.+_)?badSink(_[a-z])?$",
]
GOOD_FUNCS = [
    r"^(CWE.*_)?good$",
    r"^good(\d+|G2B\d*|B2G\d*)$",
    r"^(CWE.+_)?((helperGood(G2B|B2G)?\d*)|(good(G2B|B2G)?\d*VaSink[BG]?))$",
    r"^(CWE.+_)?good(G2B\d*|B2G\d*)?Source(_[a-z])?$",
    r"^(CWE.+_)?good(G2B\d*|B2G\d*)?Sink(_[a-z])?$",
]

CASES_PER_CWE = 40
CONTEXT_LINES_ABOVE = 15
CONTEXT_CHAR_CAP = 24000  # about 6K tokens
MAX_RULE_SHARE = 0.20
JULIET_PER_LABEL = 45


@dataclass
class Function:
    name: str
    start: int  # first line of the signature, 1-based
    end: int    # line of the closing brace


SIGNATURE = re.compile(r"^[A-Za-z_][\w \t*]*?(\w+)\s*\([^;]*\)\s*(\{.*)?$")


def function_spans(text: str) -> list[Function]:
    """Top-level functions. Both codebases put the signature at column 0 and
    the closing brace alone at column 0, so a line scan is enough."""
    spans: list[Function] = []
    start = None
    name = ""
    for n, line in enumerate(text.splitlines(), 1):
        if start is None:
            m = SIGNATURE.match(line)
            if m and m.group(1) not in ("if", "for", "while", "switch"):
                if "{" in line and line.count("{") == line.count("}"):
                    spans.append(Function(m.group(1), n, n))
                else:
                    start, name = n, m.group(1)
        elif line.rstrip() == "}":
            spans.append(Function(name, start, n))
            start = None
    return spans


def enclosing(spans: list[Function], line: int) -> Function | None:
    for f in spans:
        if f.start <= line <= f.end:
            return f
    return None


def code_context(lines: list[str], func: Function) -> tuple[str, int]:
    """The function plus up to CONTEXT_LINES_ABOVE lines, and its first line."""
    first = max(1, func.start - CONTEXT_LINES_ABOVE)
    text = "".join(lines[first - 1:func.end])
    if len(text) > CONTEXT_CHAR_CAP:
        text = text[:CONTEXT_CHAR_CAP] + "\n/* [truncated] */\n"
    return text, first


def juliet_label(func_name: str) -> str | None:
    if any(re.match(p, func_name) for p in BAD_FUNCS):
        return "TP"
    if any(re.match(p, func_name) for p in GOOD_FUNCS):
        return "FP"
    return None


def rule_cwes(run: dict) -> dict[str, list[str]]:
    """Rule id to CWE numbers, from either tool's SARIF rule metadata."""
    out: dict[str, list[str]] = {}
    for rule in run["tool"]["driver"].get("rules", []):
        found: list[str] = []
        for rel in rule.get("relationships", []):
            m = re.match(r"CWE-(\d+)", rel.get("target", {}).get("id", ""))
            if m:
                found.append(m.group(1))
        for tag in rule.get("properties", {}).get("tags", []):
            m = re.match(r"CWE-(\d+)", tag)
            if m:
                found.append(m.group(1))
        out[rule["id"]] = found
    return out


def sarif_findings(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
        return []
    findings = []
    for run in data.get("runs", []):
        tool = run["tool"]["driver"]["name"]
        cwes = rule_cwes(run)
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            start = region.get("startLine")
            if not uri or not start:
                continue
            raw_id = res.get("ruleId", "")
            findings.append({
                "tool": tool,
                # semgrep prefixes the id with the config path.
                "rule_id": re.sub(r"^.*semgrep\.rules\.", "", raw_id),
                "rule_cwes": cwes.get(raw_id, []),
                "message": (res.get("message", {}).get("text") or "").strip(),
                "uri": uri.removeprefix("file://"),
                "start_line": start,
                "end_line": region.get("endLine", start),
            })
    return findings


def cmd_sample(args: argparse.Namespace) -> None:
    root = Path(args.juliet) / "C" / "testcases"
    out = Path(args.out) / "juliet"
    if out.exists():
        shutil.rmtree(out)
    rng = random.Random(SEED)
    manifest = {}
    for cwe, dirname in JULIET_DIRS.items():
        files = sorted(p for p in (root / dirname).rglob("*.c") if "w32" not in p.name)
        cases: dict[str, list[Path]] = defaultdict(list)
        for p in files:
            case = re.sub(r"[a-e]?\.c$", "", p.name)
            cases[case].append(p)
        chosen = rng.sample(sorted(cases), min(CASES_PER_CWE, len(cases)))
        dest = out / cwe
        dest.mkdir(parents=True)
        for case in chosen:
            for p in cases[case]:
                shutil.copy2(p, dest / p.name)
        manifest[cwe] = chosen
        print(f"CWE-{cwe}: {len(chosen)} test cases, "
              f"{sum(len(cases[c]) for c in chosen)} files")
    real = Path(args.out) / "real"
    if real.exists():
        shutil.rmtree(real)
    real.mkdir(parents=True)
    shutil.copy2(REPO / "src" / "vuln_shell.c.bak", real / "vuln_shell.c")
    shutil.copy2(REPO / "src" / "hardened_shell.c", real / "hardened_shell.c")
    (Path(args.out) / "sample_manifest.json").write_text(json.dumps(manifest, indent=1))


def select(items: list[dict], total: int) -> list[dict]:
    """Rotate across CWEs, then across rules within each CWE, so no rule
    exceeds MAX_RULE_SHARE and small CWEs are drawn before large ones fill up."""
    cap = int(total * MAX_RULE_SHARE)
    groups: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for it in items:
        groups[it["cwe"]][it["rule_id"]].append(it)
    rng = random.Random(SEED)
    for by_rule in groups.values():
        for group in by_rule.values():
            rng.shuffle(group)
    turn: Counter = Counter()
    taken: Counter = Counter()
    picked: list[dict] = []
    while len(picked) < total:
        progress = False
        for cwe in sorted(groups):
            rules = [r for r in sorted(groups[cwe]) if groups[cwe][r] and taken[r] < cap]
            if not rules or len(picked) >= total:
                continue
            rule = rules[turn[cwe] % len(rules)]
            turn[cwe] += 1
            picked.append(groups[cwe][rule].pop())
            taken[rule] += 1
            progress = True
        if not progress:
            break
    return picked


def cmd_items(args: argparse.Namespace) -> None:
    work = Path(args.work)
    proposals = json.loads(Path(args.proposals).read_text()) if args.proposals else {}
    juliet_pool: dict[str, list[dict]] = {"TP": [], "FP": []}
    excluded: Counter = Counter()
    real_items: list[dict] = []
    span_cache: dict[Path, tuple[list[str], list[Function]]] = {}

    def load(path: Path) -> tuple[list[str], list[Function]]:
        if path not in span_cache:
            text = path.read_text(errors="replace")
            span_cache[path] = (text.splitlines(keepends=True), function_spans(text))
        return span_cache[path]

    for sarif in sorted((work / "sarif").glob("*.sarif")):
        for f in sarif_findings(sarif):
            path = work / f["uri"]
            if not path.exists():
                excluded["file missing"] += 1
                continue
            lines, spans = load(path)
            func = enclosing(spans, f["start_line"])
            if func is None:
                excluded["outside any function"] += 1
                continue
            rel = path.relative_to(work).as_posix()
            context, context_start = code_context(lines, func)
            base = {
                "tool": f["tool"],
                "rule_id": f["rule_id"],
                "message": f["message"],
                "file": rel,
                "start_line": f["start_line"],
                "end_line": f["end_line"],
                "function": func.name,
                "code_context": context,
                "context_start_line": context_start,
            }
            if rel.startswith("real/"):
                key = f"{rel}:{f['start_line']}:{f['rule_id']}"
                prop = proposals.get(key)
                if prop is None:
                    excluded["real finding without a proposal"] += 1
                    print(f"WARN: no label proposal for {key}", file=sys.stderr)
                    continue
                real_items.append({
                    **base,
                    "source": "c-secure-build",
                    "cwe": (f["rule_cwes"] or [""])[0],
                    "label": prop["label"],
                    "label_reason": prop["reason"],
                    "needs_human_review": True,
                })
                continue
            target = rel.split("/")[1]
            label = juliet_label(func.name)
            if label is None:
                excluded["function neither bad nor good"] += 1
                continue
            if not set(f["rule_cwes"]) & TARGET_FAMILY[target]:
                excluded[f"not the target type ({label} function)"] += 1
                continue
            juliet_pool[label].append({
                **base,
                "source": "juliet",
                "cwe": target,
                "label": label,
                "label_reason": f"Juliet: {label} per function name '{func.name}', "
                                f"rule CWE in CWE-{target} family",
                "needs_human_review": False,
            })

    juliet = select(juliet_pool["TP"], JULIET_PER_LABEL) + select(juliet_pool["FP"], JULIET_PER_LABEL)
    items = juliet + real_items
    total = len(items)
    counts = Counter(it["rule_id"] for it in items)
    over = {r: c for r, c in counts.items() if c > total * MAX_RULE_SHARE}
    for i, it in enumerate(items, 1):
        it["id"] = f"{it['source'][:3]}-{i:03d}"

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    fields = ["id", "source", "tool", "rule_id", "cwe", "message", "file",
              "start_line", "end_line", "code_context", "label",
              "label_reason", "needs_human_review", "function",
              "context_start_line"]
    with (out / "items.jsonl").open("w") as fh:
        for it in items:
            fh.write(json.dumps({k: it[k] for k in fields}) + "\n")

    labels = Counter(it["label"] for it in items)
    print(f"pool: TP {len(juliet_pool['TP'])}, FP {len(juliet_pool['FP'])} (Juliet)")
    print(f"excluded: {dict(excluded)}")
    print(f"items: {total} (TP {labels['TP']}, FP {labels['FP']}), "
          f"{len(real_items)} from c-secure-build")
    print("per rule:", dict(counts.most_common()))
    if over:
        print(f"WARN: rules above {MAX_RULE_SHARE:.0%}: {over}", file=sys.stderr)
    write_review(out / "labels_review.md", real_items, juliet, excluded, juliet_pool)


def write_review(path: Path, real: list[dict], juliet: list[dict],
                 excluded: Counter, pool: dict[str, list[dict]]) -> None:
    out = ["# Label review queue", "",
           ("Confirm or correct each proposed label for the c-secure-build findings. "
           "Juliet labels come from the User Guide v1.2 naming rules (sections 4.1 and 8) "
           "and are listed at the end for spot checks."), "",
           "## Labeling policy", "",
           ("1. `atoi` on user input (4 items): TP. atoi has undefined behavior when the value "
           "does not fit in an int (C17 7.22.1p1), so a range check after the call is too late "
           "(CERT ERR34-C). Juliet's own labels are kept: it labels `goodB2G` atoi FP because it "
           "scores only the CWE-190 flaw under test, not the conversion call."),
           "2. Unchecked `strdup` (2 items): FP. The NULL is stored and later handled.",
           ("3. Rules that flag every call to a listed API (`raptor-interesting-api-calls`) are "
           "labeled by whether the flagged call is itself a defect: TP at the C1 `strcpy` and "
           "the C4 `malloc`, FP elsewhere."), "",
           ("Edit `eval/real_label_proposals.json`, then rerun "
           "`build_items.py items` to regenerate this file and `items.jsonl`."), "",
           "| id | file:line | tool | rule | proposed | reason |", "|---|---|---|---|---|---|"]
    for it in real:
        out.append(f"| {it['id']} | {it['file']}:{it['start_line']} | {it['tool']} | "
                   f"`{it['rule_id']}` | **{it['label']}** | {it['label_reason']} |")
    out += ["", "## Juliet selection", "",
            (f"Pool before selection: {len(pool['TP'])} TP, {len(pool['FP'])} FP. "
            f"Excluded: {dict(excluded)}."), "",
            "| id | file:line | function | rule | label |", "|---|---|---|---|---|"]
    for it in juliet:
        out.append(f"| {it['id']} | {it['file']}:{it['start_line']} | `{it['function']}` | "
                   f"`{it['rule_id']}` | {it['label']} |")
    path.write_text("\n".join(out) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--juliet", required=True)
    s.add_argument("--out", required=True)
    i = sub.add_parser("items")
    i.add_argument("--work", required=True)
    i.add_argument("--proposals")
    i.add_argument("--out", required=True)
    args = parser.parse_args()
    {"sample": cmd_sample, "items": cmd_items}[args.cmd](args)


if __name__ == "__main__":
    main()
