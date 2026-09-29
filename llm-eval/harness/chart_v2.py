"""Speed vs. triage quality on the v2 test set, and the prompt's effect, as one
self-contained HTML page.

  chart_v2.py --items eval_v2/test.jsonl --results results_v2 --out results_v2/chart.html

Only complete runs (every test item answered) are plotted.
"""

from __future__ import annotations

import argparse
import html
import json
import math
from pathlib import Path

# (result name, label, family, thinking, build)
MODELS = [
    ("gemma-4-e4b-nothink", "Gemma 4 E4B", "gemma", False, "QAT Q4_0, llama.cpp b11218"),
    ("gemma-4-e4b", "Gemma 4 E4B, thinking", "gemma", True, "QAT Q4_0, llama.cpp b11218"),
    ("gemma-4-12b-nothink", "Gemma 4 12B", "gemma", False, "QAT Q4_0, llama.cpp b11218"),
    ("gemma-4-12b", "Gemma 4 12B, thinking", "gemma", True, "QAT Q4_0, llama.cpp b11218"),
    ("qwen3.5-9b-nothink", "Qwen3.5 9B", "qwen", False, "Q4_K_M, llama.cpp b11218"),
    ("claude", "Claude Opus 5.5, medium (API)", "claude", True,
     "claude-opus-5-5, effort medium"),
]
# Categorical slots 1-3 in fixed order: validated all-pairs in both modes.
FAMILIES = [("gemma", "Gemma 4", 1), ("qwen", "Qwen3.5", 2), ("claude", "Claude", 3)]
FLOOR = "nb-floor"
PROMPT1 = "prompt1"  # subdirectory with the runs of the first v2 prompt

W, H = 720, 420
LEFT, RIGHT, TOP, BOTTOM = 64, 190, 24, 56
X_MIN, X_MAX = 1.0, 40.0  # seconds per finding, log scale
Y_MIN, Y_MAX = 50.0, 100.0

DW, ROW = 760, 44
D_LEFT, D_RIGHT, D_TOP = 230, 200, 28


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def metrics(items: list[dict], res: dict[str, dict]) -> dict:
    tp = [i for i in items if i["label"] == "TP"]
    fp = [i for i in items if i["label"] == "FP"]
    kept = sum((res.get(i["id"]) or {}).get("verdict") == "TP" for i in tp)
    dismissed = sum((res.get(i["id"]) or {}).get("verdict") == "FP" for i in fp)
    lost = sum((res.get(i["id"]) or {}).get("verdict") == "FP" for i in tp)
    lat = sorted(r["latency_s"] for r in res.values() if r.get("latency_s"))
    return {
        "balanced": 50 * (kept / len(tp) + dismissed / len(fp)),
        "kept": 100 * kept / len(tp),
        "dismissed": 100 * dismissed / len(fp),
        "lost": lost,
        "n_tp": len(tp),
        "median_s": lat[len(lat) // 2] if lat else None,
        "total_min": sum(lat) / 60 if lat else None,
    }


def complete_runs(folder: Path, items: list[dict], names: list[str]) -> dict[str, dict]:
    ids = {i["id"] for i in items}
    runs = {}
    for name in names:
        p = folder / f"{name}_primary.jsonl"
        if p.exists():
            res = {r["id"]: r for r in load(p)}
            if ids <= set(res):
                runs[name] = res
    return runs


def x_px(seconds: float) -> float:
    span = math.log10(X_MAX) - math.log10(X_MIN)
    return LEFT + (math.log10(seconds) - math.log10(X_MIN)) / span * (W - LEFT - RIGHT)


def y_px(pct: float) -> float:
    return TOP + (Y_MAX - pct) / (Y_MAX - Y_MIN) * (H - TOP - BOTTOM)


def dx_px(pct: float) -> float:
    return D_LEFT + (pct - Y_MIN) / (Y_MAX - Y_MIN) * (DW - D_LEFT - D_RIGHT)


def point(x: float, y: float, family: str, filled: bool, tip: str) -> str:
    slot = {f: s for f, _, s in FAMILIES}[family]
    cls = "dot" if filled else "ring"
    return (f'<g class="pt" tabindex="0" data-tip="{html.escape(tip)}">'
            f'<circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="14"/>'
            f'<circle class="{cls} s{slot}" cx="{x:.1f}" cy="{y:.1f}" r="6"/></g>')


def scatter(items: list[dict], runs: dict, floor: float | None) -> tuple[str, list[str]]:
    svg = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-labelledby="t1 d1">',
           '<title id="t1">Speed vs. triage quality</title>',
           ('<desc id="d1">Median seconds per finding against balanced accuracy, '
            'one dot per model; see the table below.</desc>')]
    for pct in range(50, 101, 10):
        y = y_px(pct)
        svg.append(f'<line class="grid" x1="{LEFT}" x2="{W - RIGHT}" y1="{y:.1f}" y2="{y:.1f}"/>')
        svg.append(f'<text class="tick" x="{LEFT - 8}" y="{y + 4:.1f}" text-anchor="end">{pct}%</text>')
    for s in (1, 2, 5, 10, 20, 40):
        svg.append(f'<text class="tick" x="{x_px(s):.1f}" y="{H - BOTTOM + 18}" '
                   f'text-anchor="middle">{s}s</text>')
    svg.append(f'<line class="axis" x1="{LEFT}" x2="{W - RIGHT}" y1="{H - BOTTOM}" y2="{H - BOTTOM}"/>')
    svg.append(f'<text class="axis-title" x="{(LEFT + W - RIGHT) / 2:.0f}" y="{H - 14}" '
               'text-anchor="middle">Median seconds per finding (log scale, faster to the left)</text>')
    svg.append(f'<text class="axis-title" transform="translate(16 {(TOP + H - BOTTOM) / 2:.0f}) '
               'rotate(-90)" text-anchor="middle">Balanced accuracy</text>')
    if floor is not None:
        y = y_px(floor)
        svg.append(f'<line class="floor" x1="{LEFT}" x2="{W - RIGHT}" y1="{y:.1f}" y2="{y:.1f}"/>')
        svg.append(f'<text class="floor-label" x="{W - RIGHT + 6}" y="{y + 4:.1f}">'
                   f'word-count floor {floor:.1f}%</text>')
    rows = []
    for name, label, family, thinking, build in MODELS:
        if name not in runs:
            continue
        m = metrics(items, runs[name])
        x, y = x_px(m["median_s"]), y_px(m["balanced"])
        tip = (f"{label}: {m['balanced']:.1f}% balanced, {m['median_s']:.0f}s median, "
               f"real bugs kept {m['kept']:.0f}%, false positives dismissed "
               f"{m['dismissed']:.0f}%, real bugs auto-dismissed {m['lost']}/{m['n_tp']}")
        svg.append(point(x, y, family, thinking, tip))
        # Lift the label off the dashed floor line when the dot sits on it.
        ly = y - 10 if floor is not None and abs(y - y_px(floor)) < 10 else y + 4
        svg.append(f'<text class="label" x="{x + 11:.1f}" y="{ly:.1f}">{html.escape(label)}</text>')
        rows.append(f"<tr><td>{html.escape(label)}</td><td>{html.escape(build)}</td>"
                    f"<td>{m['balanced']:.1f}%</td><td>{m['kept']:.0f}%</td>"
                    f"<td>{m['dismissed']:.0f}%</td><td>{m['lost']}/{m['n_tp']}</td>"
                    f"<td>{m['median_s']:.0f}s</td><td>{m['total_min']:.0f} min</td></tr>")
    svg.append("</svg>")
    return "".join(svg), rows


def dumbbell(items: list[dict], before: dict, after: dict) -> tuple[str, list[str]]:
    pairs = [(n, lab, fam) for n, lab, fam, _, _ in MODELS if n in before and n in after]
    h = D_TOP + ROW * len(pairs) + 40
    svg = [f'<svg viewBox="0 0 {DW} {h}" role="img" aria-labelledby="t2 d2">',
           '<title id="t2">Effect of the few-shot prompt</title>',
           ('<desc id="d2">Balanced accuracy with the first prompt and with the few-shot '
            'prompt, one row per model; see the table below.</desc>')]
    for pct in range(50, 101, 10):
        x = dx_px(pct)
        svg.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{D_TOP - 8}" y2="{h - 34}"/>')
        svg.append(f'<text class="tick" x="{x:.1f}" y="{h - 16}" text-anchor="middle">{pct}%</text>')
    rows = []
    for k, (name, label, family) in enumerate(pairs):
        a, b = metrics(items, before[name]), metrics(items, after[name])
        y = D_TOP + ROW * k + ROW / 2
        xa, xb = dx_px(a["balanced"]), dx_px(b["balanced"])
        svg.append(f'<text class="label" x="{D_LEFT - 16}" y="{y + 4:.1f}" '
                   f'text-anchor="end">{html.escape(label)}</text>')
        svg.append(f'<line class="connector" x1="{xa:.1f}" x2="{xb:.1f}" y1="{y:.1f}" y2="{y:.1f}"/>')
        svg.append(f'<g class="pt" tabindex="0" data-tip="{html.escape(label)}, first prompt: '
                   f'{a["balanced"]:.1f}% balanced, {a["median_s"]:.0f}s median">'
                   f'<circle class="hit" cx="{xa:.1f}" cy="{y:.1f}" r="14"/>'
                   f'<circle class="before" cx="{xa:.1f}" cy="{y:.1f}" r="5"/></g>')
        svg.append(point(xb, y, family, True,
                         f"{label}, few-shot prompt: {b['balanced']:.1f}% balanced, "
                         f"{b['median_s']:.0f}s median"))
        delta = b["balanced"] - a["balanced"]
        svg.append(f'<text class="delta" x="{DW - D_RIGHT + 12}" y="{y + 4:.1f}">'
                   f'{delta:+.1f} pts, median {a["median_s"]:.0f}s, then {b["median_s"]:.0f}s</text>')
        rows.append(f"<tr><td>{html.escape(label)}</td><td>{a['balanced']:.1f}%</td>"
                    f"<td>{b['balanced']:.1f}%</td><td>{delta:+.1f}</td>"
                    f"<td>{a['median_s']:.0f}s</td><td>{b['median_s']:.0f}s</td></tr>")
    svg.append("</svg>")
    return "".join(svg), rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--items", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    items = load(Path(args.items))
    names = [m[0] for m in MODELS]
    runs = complete_runs(Path(args.results), items, names + [FLOOR])
    before = complete_runs(Path(args.results) / PROMPT1, items, names)
    floor = metrics(items, runs[FLOOR])["balanced"] if FLOOR in runs else None
    chart1, rows1 = scatter(items, runs, floor)
    chart2, rows2 = dumbbell(items, before, runs)
    missing = [lab for n, lab, *_ in MODELS if n not in runs]
    note_missing = (f" Not run or not finished: {html.escape(', '.join(missing))}."
                    if missing else "")

    legend1 = "".join(
        f'<span class="key"><svg width="12" height="12"><circle class="dot s{s}" cx="6" cy="6" '
        f'r="5"/></svg>{lab}</span>' for _, lab, s in FAMILIES)
    legend1 += ('<span class="key"><svg width="12" height="12"><circle class="dot mono" cx="6" '
                'cy="6" r="5"/></svg>filled: thinking</span>'
                '<span class="key"><svg width="12" height="12"><circle class="ring mono" cx="6" '
                'cy="6" r="4.5"/></svg>ring: no thinking</span>')
    legend2 = ('<span class="key"><svg width="12" height="12"><circle class="before" cx="6" cy="6" '
               'r="5"/></svg>first prompt</span><span class="key"><svg width="12" height="12">'
               '<circle class="dot mono" cx="6" cy="6" r="5"/></svg>few-shot prompt '
               '(colour = model family)</span>')

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Triage: speed vs. quality (v2 test, 117 findings)</title>
<style>
.viz-root {{
  color-scheme: light;
  --surface-1: #fcfcfb; --page: #f9f9f7; --text-primary: #0b0b0b; --text-secondary: #52514e;
  --muted: #898781; --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a;
}}
@media (prefers-color-scheme: dark) {{
  .viz-root {{
    color-scheme: dark;
    --surface-1: #1a1a19; --page: #0d0d0d; --text-primary: #ffffff; --text-secondary: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
  }}
}}
body {{ margin: 0; }}
.viz-root {{ background: var(--page); color: var(--text-primary);
  font: 14px/1.4 system-ui, sans-serif; padding: 24px; min-height: 100vh; box-sizing: border-box; }}
.card {{ background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 16px 8px; max-width: {W}px; position: relative; margin-bottom: 16px; }}
h1 {{ font-size: 16px; margin: 0 0 2px; }}
.sub {{ color: var(--text-secondary); margin: 0 0 8px; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 0 0 4px; color: var(--text-secondary);
  font-size: 12px; }}
.key {{ display: inline-flex; align-items: center; gap: 6px; }}
svg {{ width: 100%; height: auto; display: block; }}
.key svg {{ width: 12px; height: 12px; }}
.grid {{ stroke: var(--grid); stroke-width: 1; }}
.axis {{ stroke: var(--axis); stroke-width: 1; }}
.tick, .axis-title {{ fill: var(--muted); font-size: 12px; }}
.floor {{ stroke: var(--muted); stroke-width: 1.5; stroke-dasharray: 4 4; }}
.floor-label, .delta {{ fill: var(--text-secondary); font-size: 12px; }}
.s1 {{ --c: var(--series-1); }} .s2 {{ --c: var(--series-2); }} .s3 {{ --c: var(--series-3); }}
.mono {{ --c: var(--text-secondary); }}
.dot {{ fill: var(--c); stroke: var(--surface-1); stroke-width: 2; }}
.ring {{ fill: var(--surface-1); stroke: var(--c); stroke-width: 2.5; }}
.before {{ fill: var(--muted); stroke: var(--surface-1); stroke-width: 2; }}
.connector {{ stroke: var(--axis); stroke-width: 2; }}
.hit {{ fill: transparent; }}
.pt {{ cursor: default; outline: none; }}
.pt:hover circle:not(.hit), .pt:focus circle:not(.hit) {{ r: 8; }}
.label {{ fill: var(--text-primary); font-size: 12px; }}
.tip {{ position: absolute; pointer-events: none; background: var(--surface-1); color: var(--text-primary);
  border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; font-size: 12px;
  max-width: 260px; box-shadow: 0 2px 8px rgba(0,0,0,.12); display: none; }}
table {{ border-collapse: collapse; margin: 0 0 16px; max-width: 860px; width: 100%; }}
th, td {{ text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--grid); }}
th {{ color: var(--text-secondary); font-weight: 600; }}
.t1 td:nth-child(n+3), .t1 th:nth-child(n+3), .t2 td:nth-child(n+2), .t2 th:nth-child(n+2) {{
  text-align: right; font-variant-numeric: tabular-nums; }}
.note {{ color: var(--text-secondary); max-width: 860px; }}
</style></head>
<body><div class="viz-root">
<div class="card">
<h1>Triage: speed vs. quality</h1>
<p class="sub">v2 test set, 117 Juliet findings (50 real bugs, 67 false positives), few-shot prompt.
Up and left is better. Local models on an RTX 5060 Laptop (8 GB).</p>
<div class="legend">{legend1}</div>
{chart1}
<div class="tip" role="tooltip"></div>
</div>
<table class="t1"><thead><tr><th>model</th><th>build</th><th>balanced accuracy</th>
<th>real bugs kept</th><th>false positives dismissed</th><th>real bugs auto-dismissed</th>
<th>median</th><th>total</th></tr></thead><tbody>{''.join(rows1)}</tbody></table>
<div class="card">
<h1>What the few-shot prompt changed</h1>
<p class="sub">Same 117 findings. First prompt: no examples, TP defined by the rule's wording, 8K context.
Few-shot prompt: production TP definition, checklist, 9 examples from train, 16K context. No thinking
except Claude.</p>
<div class="legend">{legend2}</div>
{chart2}
<div class="tip" role="tooltip"></div>
</div>
<table class="t2"><thead><tr><th>model</th><th>first prompt</th><th>few-shot prompt</th>
<th>change (pts)</th><th>median before</th><th>median after</th></tr></thead>
<tbody>{''.join(rows2)}</tbody></table>
<p class="note">Balanced accuracy is the mean of real bugs kept and false positives dismissed.
The floor is a word-count classifier trained on the train split: a model at or below it is not
reading the code. One run per configuration, temperature 0; with 117 findings, differences under
about 10 points are within noise.{note_missing}</p>
</div>
<script>
document.querySelectorAll('.card').forEach(card => {{
  const tip = card.querySelector('.tip');
  function show(g) {{
    const b = g.querySelector('circle:not(.hit)').getBoundingClientRect(), c = card.getBoundingClientRect();
    tip.textContent = g.dataset.tip; tip.style.display = 'block';
    let left = b.left - c.left + 14, top = b.top - c.top - tip.offsetHeight - 8;
    if (left + tip.offsetWidth > c.width) left = b.left - c.left - tip.offsetWidth - 8;
    if (top < 0) top = b.bottom - c.top + 8;
    tip.style.left = left + 'px'; tip.style.top = top + 'px';
  }}
  card.querySelectorAll('.pt').forEach(g => {{
    g.addEventListener('mouseenter', () => show(g)); g.addEventListener('focus', () => show(g));
    g.addEventListener('mouseleave', () => tip.style.display = 'none');
    g.addEventListener('blur', () => tip.style.display = 'none');
  }});
}});
</script>
</body></html>
"""
    Path(args.out).write_text(page)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
