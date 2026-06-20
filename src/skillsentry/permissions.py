"""Layer 1.5 - permission / excessive-agency audit.

Correlates Layer-1 findings into capability-level judgements: annotation lies and
gross least-privilege violations (code-exec combined with broad scope / network).
"""
from __future__ import annotations

from .models import Finding, ParsedArtifact
from .rules import _mk


def permission_audit(art: ParsedArtifact, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    rule_ids = {f.rule_id for f in findings}

    # Annotation lie: declared read-only while exhibiting file/exec/network behaviour.
    if art.annotations.get("readOnlyHint") is True:
        risky = sorted(rule_ids & {"SS004", "SS005", "SS007", "SS013"})
        if risky:
            out.append(
                _mk(
                    "PERM-ANNOTATION",
                    "annotations/readOnlyHint",
                    f"readOnlyHint=true but {risky} indicate file/exec/network behaviour",
                    layer="L1.5",
                )
            )

    # Gross over-privilege: code-exec combined with broad scope and/or network egress.
    if ("SS013" in rule_ids and "SS014" in rule_ids) or (
        "SS013" in rule_ids and "SS007" in rule_ids
    ):
        out.append(
            _mk(
                "PERM-CAPABILITY",
                "permissions",
                "tool combines code-execution with broad scope and/or network egress "
                "far beyond its stated function (least-privilege violation)",
                layer="L1.5",
            )
        )
    return out
