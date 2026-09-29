"""QLoRA-distill Claude's triage answers into a local model.

  ~/llm/train-venv/bin/python train_sft.py --items ../eval_v2/teacher_pool.jsonl \
      --teacher ../results_v2/teacher/claude_train.jsonl \
      --base ~/llm/models/hf/gemma-4-E4B-it-qat-q4_0-unquantized --out ~/llm/adapters/e4b-triage

Only teacher answers that agree with the Juliet label are used, so the
student learns correct verdicts with Claude's reasoning. Prompts are built by
run_eval.build_messages without the few-shot examples, rendered with the
model's chat template and thinking off, exactly as llama-server renders them
at eval time. Loss covers the answer only. Families are held out for a
validation loss, never the test split, which train items cannot reach.
"""

from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

os.environ["RUN_EVAL_FEWSHOT"] = "none"

from unsloth import FastModel  # before datasets, transformers and trl: it patches them

# isort: split
from datasets import Dataset
from run_eval import build_messages
from trl import SFTConfig, SFTTrainer

ANSWER_KEYS = ("verdict", "confidence", "cwe", "reason")


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def render(tokenizer, item: dict, answer: dict) -> dict:
    """Prompt and completion as text; the completion is whatever the chat
    template appends for the assistant turn, end-of-turn token included."""
    messages = build_messages(item)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False,
                                           add_generation_prompt=True,
                                           enable_thinking=False)
    full = tokenizer.apply_chat_template(
        messages + [{"role": "assistant", "content": json.dumps(answer)}],
        tokenize=False, enable_thinking=False)
    if not full.startswith(prompt):
        raise SystemExit("chat template renders the assistant turn with a different "
                         "prefix than the generation prompt; cannot split prompt and answer")
    return {"prompt": prompt, "completion": full[len(prompt):], "family": item["family"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--items", required=True)
    ap.add_argument("--teacher", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--max-length", dest="max_length", type=int, default=4096)
    ap.add_argument("--val-share", dest="val_share", type=float, default=0.1)
    args = ap.parse_args()

    items = {i["id"]: i for i in load_jsonl(args.items)}
    pairs = []
    for rec in load_jsonl(args.teacher):
        item = items.get(rec["id"])
        if item and rec.get("schema_valid") and rec.get("verdict") == item["label"]:
            pairs.append((item, {k: rec[k] for k in ANSWER_KEYS}))
    if not pairs:
        raise SystemExit("no teacher answers agree with the labels")

    model, tokenizer = FastModel.from_pretrained(
        model_name=args.base, max_seq_length=args.max_length, load_in_4bit=True)
    model = FastModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.rank, lora_dropout=0.0, bias="none",
        finetune_vision_layers=False, finetune_language_layers=True,
        finetune_attention_modules=True, finetune_mlp_modules=True,
        random_state=3407)
    text_tokenizer = getattr(tokenizer, "tokenizer", tokenizer)

    rows = [render(text_tokenizer, item, answer) for item, answer in pairs]
    families = sorted({r["family"] for r in rows})
    random.Random(3407).shuffle(families)
    held = set(families[:max(1, round(len(families) * args.val_share))])
    train = [r for r in rows if r["family"] not in held]
    val = [r for r in rows if r["family"] in held]
    lengths = sorted(len(text_tokenizer(r["prompt"] + r["completion"])["input_ids"])
                     for r in rows)
    print(f"{len(pairs)} agreeing teacher answers: {len(train)} train, {len(val)} "
          f"validation ({len(held)} families); tokens median {lengths[len(lengths) // 2]}, "
          f"max {lengths[-1]}")
    if lengths[-1] > args.max_length:
        raise SystemExit(f"longest example ({lengths[-1]} tokens) exceeds --max-length")

    config = SFTConfig(
        output_dir=args.out,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        optim="adamw_8bit",
        weight_decay=0.0,
        bf16=True,
        logging_steps=5,
        eval_strategy="epoch",
        save_strategy="no",
        max_length=args.max_length,
        packing=False,
        completion_only_loss=True,
        report_to="none",
        seed=3407,
    )
    trainer = SFTTrainer(
        model=model,
        processing_class=text_tokenizer,
        train_dataset=Dataset.from_list([{k: r[k] for k in ("prompt", "completion")}
                                         for r in train]),
        eval_dataset=Dataset.from_list([{k: r[k] for k in ("prompt", "completion")}
                                        for r in val]),
        args=config,
    )
    trainer.train()
    print("final eval:", trainer.evaluate())
    model.save_pretrained(args.out)
    text_tokenizer.save_pretrained(args.out)
    Path(args.out, "held_out_families.json").write_text(json.dumps(sorted(held), indent=1))
    print(f"adapter saved to {args.out}")


if __name__ == "__main__":
    main()
