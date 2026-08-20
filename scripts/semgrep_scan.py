#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = REPO_ROOT / "src"
RULES_DIR: Path = REPO_ROOT / ".semgrep" / "rules"
SARIF_OUT: Path = REPO_ROOT / ".security" / "semgrep.sarif"


def main() -> int:
    SARIF_OUT.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        "semgrep",
        "--config", str(RULES_DIR),
        "--sarif",
        "--output", str(SARIF_OUT),
        "--quiet",
        str(SRC_DIR.relative_to(REPO_ROOT)),
    ]

    result: subprocess.CompletedProcess[str] = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )

    if result.returncode not in (0, 1):
        print(f"Semgrep scan failed (exit {result.returncode}):")
        print(result.stderr)
        return 1

    if not SARIF_OUT.exists():
        print(f"Semgrep did not produce a SARIF file at {SARIF_OUT}")
        return 1

    sarif: dict = json.loads(SARIF_OUT.read_text())
    hit_count: int = len(sarif["runs"][0]["results"])
    relative_path: Path = SARIF_OUT.relative_to(REPO_ROOT)
    print(f"Semgrep: {hit_count} finding(s) in {relative_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
