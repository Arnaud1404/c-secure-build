#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = REPO_ROOT / "src"
SARIF_OUT: Path = REPO_ROOT / ".security" / "clangsa.sarif"

CPPFLAGS: list[str] = [
    "-D_DEFAULT_SOURCE",
    "-D_POSIX_C_SOURCE=200809L",
    "-D_FORTIFY_SOURCE=3",
]
CFLAGS: list[str] = ["-std=c17"]


def find_sources() -> list[Path]:
    sources: list[Path] = []
    for path in sorted(SRC_DIR.glob("*.c")):
        sources.append(path)
    return sources


def main() -> int:
    SARIF_OUT.parent.mkdir(parents=True, exist_ok=True)

    sources: list[Path] = find_sources()
    if not sources:
        print(f"Clang SA: no source files found in {SRC_DIR.relative_to(REPO_ROOT)}")
        return 1

    combined: dict = {"version": "2.1.0", "runs": []}
    hit_count: int = 0

    for source in sources:
        cmd: list[str] = [
            "clang",
            "--analyze",
            "-Xclang", "-analyzer-output=sarif",
            *CFLAGS,
            *CPPFLAGS,
            "-o", "-",
            str(source.relative_to(REPO_ROOT)),
        ]

        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )

        if result.returncode != 0:
            print(f"Clang SA scan failed on {source.name} (exit {result.returncode}):")
            print(result.stderr)
            return 1

        run_sarif: dict = json.loads(result.stdout)
        combined["runs"].extend(run_sarif["runs"])
        for run in run_sarif["runs"]:
            hit_count += len(run["results"])

    SARIF_OUT.write_text(json.dumps(combined, indent=2) + "\n")

    relative_path: Path = SARIF_OUT.relative_to(REPO_ROOT)
    print(f"Clang SA: {hit_count} finding(s) in {relative_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
