#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
FLAWFINDER_SARIF: Path = REPO_ROOT / ".security" / "flawfinder.sarif"
SEMGREP_SARIF: Path = REPO_ROOT / ".security" / "semgrep.sarif"
CLANGSA_SARIF: Path = REPO_ROOT / ".security" / "clangsa.sarif"
MERGED_OUT: Path = REPO_ROOT / ".security" / "merged.sarif"

CWE_RE = re.compile(r"CWE-\d+")

SEVERITY_RANK: dict[str, int] = {"note": 1, "warning": 2, "error": 3}

CLANGSA_RULE_CWES: dict[str, set[str]] = {
    "unix.Malloc": {"CWE-401", "CWE-415", "CWE-416"},
    "cplusplus.NewDeleteLeaks": {"CWE-401"},
    "core.NullDereference": {"CWE-476"},
    "core.DivideZero": {"CWE-369"},
    "core.uninitialized.Assign": {"CWE-457"},
    "core.uninitialized.UndefReturn": {"CWE-457"},
    "core.uninitialized.Branch": {"CWE-457"},
    "core.uninitialized.ArraySubscript": {"CWE-457"},
    "core.uninitialized.CapturedBlockVariable": {"CWE-457"},
    "core.uninitialized.NewArraySize": {"CWE-457"},
    "core.StackAddressEscape": {"CWE-562"},
    "core.VLASize": {"CWE-1284"},
    "unix.API": {"CWE-252"},
}


class Finding:
    def __init__(
        self,
        tool: str,
        rule_id: str,
        file: str,
        line: int,
        cwes: set[str],
        level: str,
        message: str,
    ) -> None:
        self.tool = tool
        self.rule_id = rule_id
        self.file = file
        self.line = line
        self.cwes = cwes
        self.level = level
        self.message = message


def load_flawfinder(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    sarif: dict = json.loads(path.read_text())
    findings: list[Finding] = []
    for r in sarif["runs"][0]["results"]:
        text: str = r["message"]["text"]
        cwes: set[str] = set(CWE_RE.findall(text))
        loc = r["locations"][0]["physicalLocation"]
        findings.append(
            Finding(
                tool="flawfinder",
                rule_id=r["ruleId"],
                file=loc["artifactLocation"]["uri"],
                line=loc["region"]["startLine"],
                cwes=cwes,
                level=r["level"],
                message=text,
            )
        )
    return findings


def load_semgrep(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    sarif: dict = json.loads(path.read_text())
    run: dict = sarif["runs"][0]

    rules_by_id: dict[str, dict] = {}
    for rule in run["tool"]["driver"]["rules"]:
        rules_by_id[rule["id"]] = rule

    findings: list[Finding] = []
    for r in run["results"]:
        rule: dict = rules_by_id[r["ruleId"]]
        tags: list[str] = rule.get("properties", {}).get("tags", [])

        cwes: set[str] = set()
        for tag in tags:
            match = CWE_RE.match(tag)
            if match is not None:
                cwes.add(match.group())

        default_config: dict = rule.get("defaultConfiguration", {})
        level: str = default_config.get("level", "warning")
        loc = r["locations"][0]["physicalLocation"]
        findings.append(
            Finding(
                tool="semgrep",
                rule_id=r["ruleId"].rsplit(".", 1)[-1],
                file=loc["artifactLocation"]["uri"],
                line=loc["region"]["startLine"],
                cwes=cwes,
                level=level,
                message=r["message"]["text"],
            )
        )
    return findings


def load_clangsa(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    sarif: dict = json.loads(path.read_text())
    findings: list[Finding] = []
    for run in sarif["runs"]:
        for r in run["results"]:
            rule_id: str = r["ruleId"]
            cwes: set[str] = CLANGSA_RULE_CWES.get(rule_id, set())
            loc = r["locations"][0]["physicalLocation"]
            findings.append(
                Finding(
                    tool="clangsa",
                    rule_id=rule_id,
                    file=loc["artifactLocation"]["uri"],
                    line=loc["region"]["startLine"],
                    cwes=cwes,
                    level=r["level"],
                    message=r["message"]["text"],
                )
            )
    return findings


def same_defect(a: Finding, b: Finding) -> bool:
    return a.file == b.file and a.line == b.line and bool(a.cwes & b.cwes)


def group_findings(findings: list[Finding]) -> list[list[Finding]]:
    parent: list[int] = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if same_defect(findings[i], findings[j]):
                union(i, j)

    groups: dict[int, list[Finding]] = {}
    for i, finding in enumerate(findings):
        groups.setdefault(find(i), []).append(finding)
    return list(groups.values())


def severity_rank(level: str) -> int:
    return SEVERITY_RANK.get(level, 0)


def highest_level(group: list[Finding]) -> str:
    highest: str = group[0].level
    for f in group:
        if severity_rank(f.level) > severity_rank(highest):
            highest = f.level
    return highest


def merged_result(group: list[Finding]) -> dict:
    cwes: set[str] = set()
    tools: set[str] = set()
    tool_rule_ids: set[str] = set()
    attributions: list[str] = []
    for f in group:
        cwes |= f.cwes
        tools.add(f.tool)
        tool_rule_ids.add(f"{f.tool}:{f.rule_id}")
        attributions.append(f"{f.tool}:{f.rule_id}")

    level: str = highest_level(group)
    attribution: str = "; ".join(attributions)
    rule_id: str = "unclassified"
    if cwes:
        rule_id = "/".join(sorted(cwes))

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"[{attribution}] {group[0].message}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": group[0].file},
                    "region": {"startLine": group[0].line},
                }
            }
        ],
        "properties": {
            "cwe": sorted(cwes),
            "tools": sorted(tools),
            "tool_rule_ids": sorted(tool_rule_ids),
        },
    }


def sort_key(result: dict) -> tuple[int, str]:
    region: dict = result["locations"][0]["physicalLocation"]["region"]
    return (region["startLine"], result["ruleId"])


def main() -> int:
    ff_findings: list[Finding] = load_flawfinder(FLAWFINDER_SARIF)
    sg_findings: list[Finding] = load_semgrep(SEMGREP_SARIF)
    csa_findings: list[Finding] = load_clangsa(CLANGSA_SARIF)
    findings: list[Finding] = ff_findings + sg_findings + csa_findings
    groups: list[list[Finding]] = group_findings(findings)

    results: list[dict] = []
    for group in groups:
        results.append(merged_result(group))
    results.sort(key=sort_key)

    driver: dict = {
        "name": "c-secure-build-sarif-merge",
        "version": "1.0.0",
    }
    sarif: dict = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }

    MERGED_OUT.parent.mkdir(parents=True, exist_ok=True)
    MERGED_OUT.write_text(json.dumps(sarif, indent=2) + "\n")

    merged_count: int = 0
    for group in groups:
        if len(group) > 1:
            merged_count += 1

    relative_path: Path = MERGED_OUT.relative_to(REPO_ROOT)
    print(
        f"SARIF merge: {len(findings)} raw finding(s) -> "
        f"{len(results)} reconciled ({merged_count} merged across tools) "
        f"in {relative_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
