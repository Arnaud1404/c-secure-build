import json
from pathlib import Path

import build_v2

ROOT = Path(__file__).resolve().parents[1]


def families(path: Path) -> set[str]:
    return {json.loads(line)["family"] for line in path.read_text().splitlines()}


def test_family_ignores_the_flow_number() -> None:
    first = build_v2.family(Path("CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_01.c"))
    last = build_v2.family(Path("CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_18.c"))
    assert first == last == "CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy"


def test_items_record_the_family_of_their_file() -> None:
    for name in ("test.jsonl", "teacher_pool.jsonl"):
        for line in (ROOT / "eval_v2" / name).read_text().splitlines():
            item = json.loads(line)
            assert build_v2.family(Path(item["key"].split(":")[0])) == item["family"], item["id"]


def test_no_test_family_appears_in_train() -> None:
    test = families(ROOT / "eval_v2" / "test.jsonl")
    assert len(test) == 39
    assert not test & families(ROOT / "eval_v2" / "teacher_pool.jsonl")


def test_few_shot_examples_come_from_outside_the_test_families() -> None:
    examples = json.loads((ROOT / "harness" / "fewshot.json").read_text())
    assert not {ex["family"] for ex in examples} & families(ROOT / "eval_v2" / "test.jsonl")
