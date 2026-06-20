"""Render a ScanReport to JSON and to human-readable markdown."""
from __future__ import annotations

from .models import SEVERITY_RANK, ScanReport

_SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def to_dict(report: ScanReport) -> dict:
    from . import __version__

    return {
        "scanner": {"name": "SkillSentry", "version": __version__, "rulesetVersion": "1.0"},
        "target": {"type": report.target_type, "path": report.target_path},
        "summary": {
            "riskScore": report.risk_score(),
            "riskLevel": report.risk_level(),
            "verdict": report.verdict(),
            "findingsCount": len(report.findings),
            "high": len(report.high),
            "medium": len(report.medium),
            "low": len(report.low),
        },
        "rugPull": {
            "snapshotPresent": report.rug_pull.snapshot_present,
            "mutated": report.rug_pull.mutated,
            "changedFields": report.rug_pull.changed_fields,
            "baselineSha256": report.rug_pull.baseline_sha256,
            "currentSha256": report.rug_pull.current_sha256,
        },
        "normalization": {
            "invisibleCodepoints": report.normalization.invisible_codepoints,
            "tagBlock": report.normalization.tag_block,
            "ansiSequences": report.normalization.ansi_sequences,
            "htmlComments": report.normalization.html_comments,
            "base64Blocks": report.normalization.base64_blocks,
        },
        "findings": [
            {
                "ruleId": f.rule_id,
                "ruleName": f.rule_name,
                "severity": f.severity,
                "confidence": f.confidence,
                "layer": f.layer,
                "targetField": f.target_field,
                "evidence": f.evidence,
                "taxonomy": f.taxonomy,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in _sorted(report.findings)
        ],
        "errors": report.errors,
    }


def _sorted(findings):
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id))


def to_markdown(report: ScanReport) -> str:
    lvl = report.risk_level()
    lines = [
        "# SkillSentry Report",
        "",
        f"**Target:** `{report.target_path}` ({report.target_type})  ",
        f"**Risk:** {lvl.upper()} ({report.risk_score()}/100) — verdict: **{report.verdict()}**  ",
        f"**Findings:** {len(report.findings)} "
        f"(high {len(report.high)}, medium {len(report.medium)}, low {len(report.low)})",
        "",
    ]
    if report.rug_pull.mutated:
        lines += [
            "> ⚠️ **Rug-pull detected:** the tool definition changed after approval "
            f"(changed: {', '.join(report.rug_pull.changed_fields) or 'content'}).",
            "",
        ]
    if not report.findings:
        lines += ["✅ No findings. Nothing suspicious detected.", ""]
    else:
        lines += ["## Findings", ""]
        for f in _sorted(report.findings):
            icon = _SEV_ICON.get(f.severity, "•")
            conf = "" if f.confidence >= 1.0 else f" _(confidence {f.confidence:.0%})_"
            lines += [
                f"### {icon} `{f.rule_id}` {f.rule_name} — {f.severity.upper()}{conf}",
                f"- **Field:** `{f.target_field}`",
                f"- **Evidence:** {f.evidence}",
                f"- **Why:** {f.description}",
                f"- **Fix:** {f.remediation}",
                f"- **Maps to:** {f.taxonomy}",
                "",
            ]
    norm = report.normalization
    if any([norm.invisible_codepoints, norm.tag_block, norm.ansi_sequences, norm.html_comments]):
        lines += [
            "## Normalization (Layer 0)",
            f"- invisible codepoints: {norm.invisible_codepoints}",
            f"- unicode-tag codepoints: {norm.tag_block}",
            f"- ANSI sequences: {norm.ansi_sequences}",
            f"- HTML comments: {norm.html_comments}",
            "",
        ]
    return "\n".join(lines)
