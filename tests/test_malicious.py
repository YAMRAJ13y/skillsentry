"""Malicious fixtures must trip the expected rules and be blocked."""
from __future__ import annotations

import pathlib

from skillsentry import scan

FX = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "malicious"


def _ids(report):
    return {f.rule_id for f in report.findings}


def test_tool_poisoning_add_numbers():
    report = scan(str(FX / "add_numbers.tool.json"))
    got = _ids(report)
    for rid in ("SS001", "SS002", "SS003", "SS004", "SS005", "SS006", "PERM-ANNOTATION"):
        assert rid in got, (rid, sorted(got))
    assert report.risk_level() in ("high", "critical")
    assert report.verdict() == "block"


def test_rug_pull_detected():
    report = scan(str(FX / "weather_lookup.rugpull.json"))
    assert report.rug_pull.mutated is True
    assert "description" in report.rug_pull.changed_fields
    got = _ids(report)
    for rid in ("RUGPULL", "SS001", "SS003", "SS004", "SS005"):
        assert rid in got, (rid, sorted(got))
    assert report.verdict() == "block"


def test_excessive_permission_skill():
    report = scan(str(FX / "file_helper" / "SKILL.md"))
    got = _ids(report)
    for rid in ("SS004", "SS006", "SS007", "SS013", "SS014", "PERM-CAPABILITY"):
        assert rid in got, (rid, sorted(got))
    assert report.verdict() == "block"
