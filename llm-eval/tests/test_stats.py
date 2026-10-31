from pathlib import Path

import stats

ROOT = Path(__file__).resolve().parents[1]


def item(item_id: str, label: str) -> dict:
    return {"id": item_id, "label": label}


def test_wilson_matches_the_published_intervals() -> None:
    assert stats.wilson(6, 50) == "6-24%"
    assert stats.wilson(55, 67) == "71-89%"


def test_wilson_stays_in_range_at_the_bounds() -> None:
    assert stats.wilson(0, 50) == "0-7%"
    assert stats.wilson(50, 50) == "93-100%"
    assert stats.wilson(0, 0) == "n/a"


def test_missing_answers_count_as_wrong() -> None:
    items = [item("a", "TP"), item("b", "TP"), item("c", "FP"), item("d", "FP")]
    # One TP kept, one FP dismissed, the other two unanswered: (50% + 50%) / 2.
    res = {"a": {"verdict": "TP"}, "c": {"verdict": "FP"}}
    assert "| 50.0% | 50.0% | 50.0% |" in stats.row("m", items, res)


def test_filter_counts_only_fp_verdicts_as_removals() -> None:
    items = [item("a", "TP"), item("b", "TP"), item("c", "FP")]
    res = {"a": {"verdict": "FP"}, "b": {"verdict": "UNCERTAIN"}, "c": {"verdict": "UNCERTAIN"}}
    assert stats.filter_row("m", items, res).startswith("| m | 1/2 ")


def test_published_score_comes_from_the_committed_results() -> None:
    items = stats.load(ROOT / "eval_v2" / "test.jsonl")
    results = stats.load(ROOT / "results_v2" / "gemma-4-e4b_primary.jsonl")
    res = {r["id"]: r for r in results}
    assert "| 88.0% | 82.1% | 85.0% |" in stats.row("gemma-4-e4b", items, res)
