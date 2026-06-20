"""Benign fixtures must produce zero findings (no false positives)."""
from __future__ import annotations

import pathlib

from skillsentry import scan

FX = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "benign"


def test_benign_tool_is_clean():
    report = scan(str(FX / "get_weather.tool.json"))
    assert report.findings == [], [f.rule_id for f in report.findings]
    assert report.risk_level() == "info"
    assert report.verdict() == "allow"


def test_benign_skill_is_clean():
    report = scan(str(FX / "search_docs" / "SKILL.md"))
    assert [f.rule_id for f in report.findings] == []
    assert report.verdict() == "allow"


def test_benign_config_is_clean():
    report = scan(str(FX / "mcp_config.json"))
    assert report.findings == []
