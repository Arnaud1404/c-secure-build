import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "cvss", Path(__file__).resolve().parent.parent / "scripts" / "cvss.py"
)
cvss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cvss)


# Base scores as published by NVD for these CVEs, or by the FIRST calculator.
@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # CVE-2021-44228
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # CVE-2014-0160
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score(vector, score):
    assert cvss.base_score(vector) == score


def test_metric_order_does_not_matter():
    assert cvss.base_score("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N") == 9.8


@pytest.mark.parametrize(
    ("value", "rounded"), [(4.02, 4.1), (4.0, 4.0), (4.000000000000001, 4.0)]
)
def test_roundup(value, rounded):
    assert cvss.roundup(value) == rounded


@pytest.mark.parametrize(
    ("score", "label"),
    [(0.0, "None"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (7.0, "High"), (9.0, "Critical")],
)
def test_severity(score, label):
    assert cvss.severity(score) == label


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no prefix
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # other version
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # A missing
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # AV twice
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F",  # temporal metric
    ],
)
def test_rejects_malformed_vectors(vector):
    with pytest.raises(ValueError):
        cvss.base_score(vector)


def test_cli_exit_codes(capsys):
    assert cvss.main(["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]) == 0
    assert "9.8 Critical" in capsys.readouterr().out
    assert cvss.main(["CVSS:3.1/AV:N"]) == 2
    assert cvss.main([]) == 2
