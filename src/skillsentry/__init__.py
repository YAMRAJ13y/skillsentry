"""SkillSentry - a semantic scanner for malicious MCP servers and agent skills.

Detects prompt-injection, tool-poisoning, rug-pulls, hidden-content smuggling, and
excessive agency in MCP tool definitions, MCP server configs, and agent SKILL.md
files. Findings map to OWASP Agentic (ASI) / OWASP LLM Top 10 / MITRE ATLAS.

Public API:
    scan(path, use_llm=False) -> ScanReport
    to_dict(report) / to_markdown(report)
    detect ruleset in skillsentry.rules (RULES, RULES_META)
"""
from __future__ import annotations

from .detector import scan
from .models import Finding, ScanReport
from .report import to_dict, to_markdown

__version__ = "0.1.0"

__all__ = ["scan", "ScanReport", "Finding", "to_dict", "to_markdown", "__version__"]
