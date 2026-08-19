#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = REPO_ROOT / "src"
SARIF_OUT: Path = REPO_ROOT / ".security" / "flawfinder.sarif"


def level_to_severity(level: int) -> str:
    if level >= 4:
        return "error"
    if level >= 2:
        return "warning"
    return "note"


def is_suppressed(filepath: str, line_number: int) -> bool:
    file_path: Path = REPO_ROOT / filepath
    if not file_path.exists():
        return False
    try:
        with open(file_path, "r") as f:
            lines: list[str] = f.readlines()
        if line_number < 1 or line_number > len(lines):
            return False
        source_line: str = lines[line_number - 1]
        if "flawfinder:ignore" in source_line:
            return True
    except Exception:
        return False
    return False


def parse_flawfinder_hit(line: str) -> dict | None:
    parts: list[str] = line.split(":", 3)
    if len(parts) != 4:
        return None

    filepath: str = parts[0]
    if not parts[1].isdigit() or not parts[2].isdigit():
        return None

    line_number: int = int(parts[1])
    column_number: int = int(parts[2])
    rest: str = parts[3]

    level_start: int = rest.find("[")
    level_end: int = rest.find("]")
    if level_start < 0 or level_end < 0 or level_end <= level_start:
        return None

    level_str: str = rest[level_start + 1:level_end]
    if not level_str.isdigit():
        return None
    level: int = int(level_str)

    cat_start: int = rest.find("(")
    cat_end: int = rest.find(")")
    if cat_start < 0 or cat_end < 0 or cat_end <= cat_start:
        return None

    category: str = rest[cat_start + 1:cat_end]

    after_category: str = rest[cat_end + 1:]
    colon_pos: int = after_category.find(":")
    if colon_pos < 0:
        return None

    function: str = after_category[:colon_pos].strip()
    message: str = after_category[colon_pos + 1:].strip()

    return {
        "filepath": filepath,
        "line_number": line_number,
        "column_number": column_number,
        "level": level,
        "category": category,
        "function": function,
        "message": message,
    }


def main() -> int:
    cmd: list[str] = [
        "flawfinder",
        "--singleline",
        "--columns",
        "--dataonly",
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

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for line in result.stdout.splitlines():
        hit: dict | None = parse_flawfinder_hit(line)
        if hit is None:
            continue

        filepath: str = hit["filepath"]
        line_number: int = hit["line_number"]
        if is_suppressed(filepath, line_number):
            continue

        level: int = hit["level"]
        category: str = hit["category"]
        function: str = hit["function"]
        column_number: int = hit["column_number"]
        message: str = hit["message"]

        rule_id: str = f"{category}/{function}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"Flawfinder: {function}"},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": level_to_severity(level),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": filepath.replace("\\", "/")
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": column_number,
                            },
                        }
                    }
                ],
                "properties": {
                    "flawfinderRiskLevel": level,
                    "security-severity": str(level),
                },
            }
        )

    sarif: dict = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Flawfinder",
                        "version": "2.0.11",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    SARIF_OUT.parent.mkdir(parents=True, exist_ok=True)
    SARIF_OUT.write_text(json.dumps(sarif, indent=2) + "\n")

    hit_count: int = len(results)
    relative_path: Path = SARIF_OUT.relative_to(REPO_ROOT)
    print(f"Flawfinder: {hit_count} finding(s) in {relative_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
