#!/usr/bin/env bash
# Claude run: Opus 5.5 at medium effort, then Sonnet 5 for anything Opus
# refused or failed on. Sends the code to Anthropic.
set -eu
cd "$(dirname "$0")/../.."
R=llm-eval/results
python3 llm-eval/harness/run_eval.py run --items llm-eval/eval/items.jsonl --backend claude \
    --claude-model claude-opus-5-5 --effort medium --model claude --source juliet \
    --out "$R/claude_primary.jsonl" || true
python3 - <<'PY'
import json
p = "llm-eval/results/claude_primary.jsonl"
rows = [json.loads(l) for l in open(p)]
failed = {r["id"] for r in rows if not r.get("schema_valid")}
keep = [r for r in rows if r["id"] not in failed]
open(p, "w").write("".join(json.dumps(r) + "\n" for r in keep))
print(f"{len(failed)} items to retry with Sonnet 5")
PY
python3 llm-eval/harness/run_eval.py run --items llm-eval/eval/items.jsonl --backend claude \
    --claude-model claude-sonnet-5 --effort medium --model claude --source juliet \
    --out "$R/claude_primary.jsonl"
