import json
from pathlib import Path

import pytest
import run_eval

ROOT = Path(__file__).resolve().parents[1]

JULIET_LIKE = """\
#ifndef OMITBAD
void CWE121_dest_char_declare_cpy_12_bad()
{
    char data[10];
    /* FLAW: no room for the terminator */
    strcpy(data, "BADSOURCE");
}
#endif /* OMITBAD */

static void goodG2B()
{
    printLine("Benign input, fixed");
    CWE121_dest_char_declare_cpy_12_bad();
}
"""


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / "eval_v2" / name).read_text().splitlines()]


def test_scrub_removes_every_label_word() -> None:
    out = run_eval.scrub(JULIET_LIKE)
    assert run_eval.LEAK_WORDS.search(out) is None


def test_scrub_keeps_line_numbers_and_string_lengths() -> None:
    out = run_eval.scrub(JULIET_LIKE)
    assert out.count("\n") == JULIET_LIKE.count("\n")
    assert 'strcpy(data, "xxxxxxxxx");' in out


def test_scrub_renames_each_labelled_name_once() -> None:
    out = run_eval.scrub(JULIET_LIKE)
    assert out.count("id_1") == 2
    assert "static void id_2()" in out


def test_scrub_drops_a_comment_the_context_opens_inside() -> None:
    out = run_eval.scrub(" * FLAW: overflow below\n */\nint n;\n")
    assert out == "\n\nint n;\n"


def test_scrub_refuses_a_label_word_it_cannot_remove() -> None:
    with pytest.raises(run_eval.LeakError):
        run_eval.scrub("int fix_count = 0;\n")


@pytest.mark.parametrize("name", ["test.jsonl", "teacher_pool.jsonl"])
def test_committed_prompts_carry_no_label_word(name: str) -> None:
    # The tool name is the only allowed match: "Flawfinder" contains "flaw".
    for item in load(name):
        user = run_eval.build_messages(item)[1]["content"].replace("Flawfinder", "")
        assert run_eval.LEAK_WORDS.search(user) is None, item["id"]
