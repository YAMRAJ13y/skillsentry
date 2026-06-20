"""Orchestrator: parse -> normalize -> Layer 1 rules -> permission audit -> (LLM)."""
from __future__ import annotations

from .llm import llm_classify
from .models import NormalizationInfo, ScanReport
from .normalize import deobfuscate
from .parsers import parse_artifact
from .permissions import permission_audit
from .rules import RULES, _mk


def scan(path: str, use_llm: bool = False) -> ScanReport:
    art = parse_artifact(path)
    report = ScanReport(art.target_type, path)
    report.errors = list(art.errors)
    if art.rug_pull:
        report.rug_pull = art.rug_pull

    agg = NormalizationInfo()
    for f in art.fields:
        f.norm, info = deobfuscate(f.raw)
        agg.invisible_codepoints += info.invisible_codepoints
        agg.tag_block += info.tag_block
        agg.ansi_sequences += info.ansi_sequences
        agg.html_comments += info.html_comments
        agg.base64_blocks += info.base64_blocks
    report.normalization = agg

    findings = []
    for rule in RULES:
        findings.extend(rule(art))

    if art.rug_pull and art.rug_pull.mutated:
        ev = (
            f"baseline {art.rug_pull.baseline_sha256[:12]} != "
            f"current {art.rug_pull.current_sha256[:12]}"
        )
        if art.rug_pull.changed_fields:
            ev += "; changed: " + ", ".join(art.rug_pull.changed_fields)
        findings.append(_mk("RUGPULL", art.path, ev))

    findings.extend(permission_audit(art, findings))

    if use_llm:
        findings.extend(llm_classify(art, findings))

    report.findings = findings
    return report
