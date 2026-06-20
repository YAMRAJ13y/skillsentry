"""Core data models for SkillSentry scan results."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_WEIGHT = {"high": 40, "medium": 15, "low": 5}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Field:
    """One model-visible text span extracted from an artifact."""

    pointer: str
    raw: str
    kind: str  # description|title|default|enum|name|command|args|env|url|headers|
    #            param_name|scope|allowed_tools|body|frontmatter
    norm: str = ""  # deobfuscated view (filled by the normalizer)
    required: bool = False  # for param_name fields


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    target_field: str
    evidence: str
    taxonomy: str
    description: str
    remediation: str
    layer: str = "L1"
    confidence: float = 1.0


@dataclass
class RugPull:
    snapshot_present: bool = False
    mutated: bool = False
    changed_fields: list[str] = field(default_factory=list)
    baseline_sha256: str | None = None
    current_sha256: str | None = None


@dataclass
class NormalizationInfo:
    invisible_codepoints: int = 0
    tag_block: int = 0
    ansi_sequences: int = 0
    html_comments: int = 0
    base64_blocks: int = 0


@dataclass
class ParsedArtifact:
    target_type: str
    path: str
    fields: list[Field] = field(default_factory=list)
    additional_properties_open: bool = False
    tool_names: list[str] = field(default_factory=list)
    annotations: dict = field(default_factory=dict)
    rug_pull: RugPull | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    target_type: str
    target_path: str
    findings: list[Finding] = field(default_factory=list)
    rug_pull: RugPull = field(default_factory=RugPull)
    normalization: NormalizationInfo = field(default_factory=NormalizationInfo)
    errors: list[str] = field(default_factory=list)

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "low"]

    def risk_score(self) -> int:
        score = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        if self.rug_pull.mutated:
            score += 40
        return min(100, score)

    def risk_level(self) -> str:
        s = self.risk_score()
        if s >= 70:
            return "critical"
        if s >= 40:
            return "high"
        if s >= 15:
            return "medium"
        if s > 0:
            return "low"
        return "info"

    def verdict(self) -> str:
        return {"critical": "block", "high": "block", "medium": "review", "low": "review"}.get(
            self.risk_level(), "allow"
        )
