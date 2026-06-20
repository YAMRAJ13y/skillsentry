r"""Layer 0 - normalization / de-obfuscation.

Surfaces hidden content (invisible Unicode, Unicode-tag smuggling, ANSI escapes,
HTML comments, base64 blobs) so later heuristic rules operate on what the *agent*
actually reads, not on what a human sees. Obfuscation is surfaced, not evaded.
"""
from __future__ import annotations

import base64
import re

from .models import NormalizationInfo

# Zero-width, soft hyphen, and bidirectional control characters.
INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)
# Unicode Tag block (E0000-E007F) - "ASCII smuggling".
TAG_BLOCK = re.compile("[\U000e0000-\U000e007f]")
# Variation selectors.
VARIATION = re.compile("[\ufe00-\ufe0f]")
# ANSI escape sequences: CSI (colour/cursor) and OSC (hyperlink) forms.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def deobfuscate(text: str) -> tuple[str, NormalizationInfo]:
    """Return (normalized_text, info). ``normalized_text`` keeps hidden content visible."""
    info = NormalizationInfo()
    info.invisible_codepoints = len(INVISIBLE.findall(text)) + len(VARIATION.findall(text))
    info.tag_block = len(TAG_BLOCK.findall(text))
    info.ansi_sequences = len(ANSI.findall(text))
    info.html_comments = len(HTML_COMMENT.findall(text))

    norm = ANSI.sub("", text)
    norm = TAG_BLOCK.sub("", norm)
    norm = INVISIBLE.sub("", norm)
    norm = VARIATION.sub("", norm)

    decoded: list[str] = []
    for m in _B64.finditer(norm):
        try:
            d = base64.b64decode(m.group(0), validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if d and sum(c.isprintable() or c.isspace() for c in d) / len(d) > 0.85:
            decoded.append(d)
    if decoded:
        info.base64_blocks = len(decoded)
        norm = norm + "\n" + "\n".join(decoded)

    return norm, info
