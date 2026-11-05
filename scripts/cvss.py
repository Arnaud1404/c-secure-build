"""CVSS 3.1 base score from a vector string, as defined in the FIRST specification.

Usage: python scripts/cvss.py 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' [...]
Exit 0 when every vector parses, 2 otherwise.
"""

import math
import sys

PREFIX = "CVSS:3.1/"

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# A changed scope raises the weight of a required privilege: the attacker escapes it.
PR_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def roundup(value: float) -> float:
    # Spec appendix A: integer arithmetic, so 4.000000001 from float error stays 4.0.
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    if not vector.startswith(PREFIX):
        raise ValueError(f"expected the {PREFIX} prefix: {vector}")
    metrics: dict[str, str] = {}
    for part in vector[len(PREFIX):].split("/"):
        name, sep, value = part.partition(":")
        if not sep or name not in WEIGHTS:
            raise ValueError(f"unknown metric {part!r}")
        if name in metrics:
            raise ValueError(f"metric {name} given twice")
        if value not in WEIGHTS[name]:
            raise ValueError(f"bad value {value!r} for {name}")
        metrics[name] = value
    missing = [name for name in WEIGHTS if name not in metrics]
    if missing:
        raise ValueError(f"missing metrics: {', '.join(missing)}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (
        (1 - WEIGHTS["C"][m["C"]])
        * (1 - WEIGHTS["I"][m["I"]])
        * (1 - WEIGHTS["A"][m["A"]])
    )
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    pr = PR_SCOPE_CHANGED[m["PR"]] if changed else WEIGHTS["PR"][m["PR"]]
    exploitability = (
        8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * pr * WEIGHTS["UI"][m["UI"]]
    )
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    status = 0
    for vector in argv:
        try:
            score = base_score(vector)
        except ValueError as err:
            print(f"cvss: {err}", file=sys.stderr)
            status = 2
            continue
        print(f"{score:4.1f} {severity(score):8} {vector}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
