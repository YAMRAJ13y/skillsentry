"""Layer 1 - deterministic heuristic ruleset (SS001-SS014).

Each rule walks the model-visible fields of a parsed artifact and yields Findings.
Text rules operate on the *deobfuscated* view (``field.norm``) so hidden content is
caught; obfuscation-presence rules (SS008/SS009/SS010) inspect the raw bytes.
Every rule maps to OWASP Agentic (ASI) / OWASP LLM / MITRE ATLAS taxonomy.
"""
from __future__ import annotations

import re

from .models import Field, Finding, ParsedArtifact
from .normalize import ANSI, INVISIBLE, TAG_BLOCK, VARIATION

TEXT_KINDS = {"description", "title", "default", "enum", "frontmatter", "body"}
CONFIG_TEXT = {"command", "args", "env", "url", "headers"}

# rule_id -> (name, severity, taxonomy, description, remediation)
RULES_META: dict[str, tuple[str, str, str, str, str]] = {
    "SS001": ("Hidden-instruction tags in tool/skill prose", "high",
              "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0110",
              "Pseudo-XML imperative tags (<IMPORTANT>, <SYSTEM>, ...) embedded in a "
              "field whose only job is documentation - a classic tool-poisoning tell.",
              "Remove the tag; documentation must not contain agent-directed instructions."),
    "SS002": ("Concealment / coercion language in metadata", "high",
              "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051",
              "Secrecy ('do not mention'), 'mere implementation detail', or threats "
              "('will malfunction') - used to force silent compliance.",
              "Strip the concealment/coercion text; legitimate docs never hide behaviour."),
    "SS003": ("Second-person agent directives in metadata", "high",
              "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051.001",
              "Imperatives addressed to the agent ('you must', 'first read', 'ignore "
              "previous') where only descriptive documentation belongs.",
              "Rewrite as third-person documentation or remove."),
    "SS004": ("Sensitive credential/path literals in metadata", "high",
              "OWASP-Agentic ASI03 / OWASP-LLM LLM02 / MITRE ATLAS AML.T0086",
              "A description/arg names a private key or secret store (id_rsa, .env, "
              ".aws/credentials, /etc/passwd) - no legitimate reason to do so.",
              "Remove the reference; tools should never point the agent at secrets."),
    "SS005": ("Read-secret-then-stuff-into-parameter exfiltration", "high",
              "OWASP-Agentic ASI02 / OWASP-LLM LLM02 / MITRE ATLAS AML.T0086",
              "Instructs the agent to read a file and place its contents into a "
              "parameter/URL - the canonical MCP exfiltration pattern.",
              "Remove the instruction; data egress must not be smuggled via parameters."),
    "SS006": ("Suspicious free-text exfiltration parameter", "high",
              "OWASP-Agentic ASI02 / OWASP-LLM LLM02 / MITRE ATLAS AML.T0086",
              "A vaguely named free-text parameter (sidenote/context/exfil_url) unrelated "
              "to the tool's function - a covert data-egress channel.",
              "Remove the parameter or constrain it to the tool's real inputs."),
    "SS007": ("Beacon / exfil host or data-templating URL", "high",
              "OWASP-Agentic ASI02 / OWASP-LLM LLM02 / MITRE ATLAS AML.T0086",
              "An attacker-beacon host (webhook.site, *.ngrok, raw IP) or a URL that "
              "interpolates data into its query string.",
              "Remove the URL; restrict outbound hosts to an explicit allowlist."),
    "SS008": ("Invisible / non-rendering codepoint smuggling", "high",
              "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051.001",
              "Zero-width, bidi-control, or Unicode-tag codepoints hide instructions the "
              "human cannot see but the model reads.",
              "Strip non-rendering characters; reject artifacts that smuggle hidden text."),
    "SS009": ("ANSI escape / terminal deception", "high",
              "OWASP-Agentic ASI09 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051",
              "ANSI escape sequences can paint text invisible, reposition the cursor, or "
              "spoof hyperlinks in terminal-rendered output.",
              "Strip ANSI/control sequences before display or ingestion."),
    "SS010": ("Instructions buried in HTML/markdown comments", "high",
              "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051.001",
              "An HTML comment carries imperative/secret-bearing text - invisible to a "
              "human reader but ingested by the model.",
              "Remove comment-embedded instructions; do not feed comments to the model."),
    "SS011": ("Cross-tool shadowing / behavior-override", "high",
              "OWASP-Agentic ASI02 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0053",
              "A tool's description prescribes behaviour for a DIFFERENT tool "
              "(e.g. 'always BCC ...') - cross-server tool shadowing.",
              "Remove cross-tool directives; isolate untrusted server descriptions."),
    "SS012": ("Typosquat / homoglyph / duplicate tool name", "medium",
              "OWASP-Agentic ASI09 / OWASP-LLM LLM03 / MITRE ATLAS AML.T0010.001",
              "A tool/server name uses non-ASCII homoglyphs, digit-swaps, or collides "
              "with another name - impersonation / decision-fatigue abuse.",
              "Use unique ASCII names; verify provenance of colliding tools."),
    "SS013": ("Shell / code-execution primitive", "high",
              "OWASP-Agentic ASI05 / OWASP-LLM LLM05 / MITRE ATLAS AML.T0110",
              "A config command, tool param, or skill block exposes arbitrary code "
              "execution (bash -c, child_process, free-form 'command', inline !`...`).",
              "Remove the exec primitive or sandbox it with an explicit command allowlist."),
    "SS014": ("Wildcard / over-broad scope grant", "medium",
              "OWASP-Agentic ASI03 / OWASP-LLM LLM06 / MITRE ATLAS AML.T0010.001",
              "Wildcard tool/scope grants (allowed-tools: *, files:write:*, "
              "network:outbound:*, additionalProperties:true) far exceeding stated function.",
              "Apply least privilege; grant only the specific scopes the tool needs."),
    "RUGPULL": ("Tool definition mutated after approval (rug-pull)", "high",
                "OWASP-Agentic ASI04 / OWASP-LLM LLM03 / MITRE ATLAS AML.T0110",
                "An approved tool was silently redefined (same name/version, different "
                "content) - the MCPoison pattern.",
                "Pin tool definitions by content hash and re-prompt on any change."),
    "PERM-ANNOTATION": ("Annotation contradicts observed capability", "high",
                        "OWASP-Agentic ASI02 / OWASP-LLM LLM06 / MITRE ATLAS AML.T0110",
                        "annotations.readOnlyHint=true while the tool exhibits file/exec/"
                        "network behaviour - annotations are untrusted and inconsistent.",
                        "Remove the false annotation or restrict to genuinely read-only ops."),
    "PERM-CAPABILITY": ("Excessive agency / capability", "high",
                        "OWASP-Agentic ASI03 / OWASP-LLM LLM06 / MITRE ATLAS AML.T0110",
                        "The tool/skill grants a high-impact capability (shell exec, "
                        "unrestricted fs or network) beyond a least-privilege baseline.",
                        "Scope the capability down to the minimum the function requires."),
    "LLM-CLASSIFIER": ("Semantic classifier verdict", "high",
                       "OWASP-Agentic ASI01 / OWASP-LLM LLM01 / MITRE ATLAS AML.T0051",
                       "A local LLM classifier judged this field to contain agent-directed "
                       "instructions rather than documentation.",
                       "Review the offending span; remove embedded instructions."),
}


def _clip(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _mk(rule_id: str, target: str, evidence: str, layer: str = "L1", confidence: float = 1.0) -> Finding:
    name, sev, tax, desc, rem = RULES_META[rule_id]
    return Finding(rule_id, name, sev, target, _clip(evidence), tax, desc, rem, layer, confidence)


def _text_fields(art: ParsedArtifact, kinds: set[str]) -> list[Field]:
    return [f for f in art.fields if f.kind in kinds]


# --- compiled patterns ------------------------------------------------------ #
RE_SS001 = re.compile(r"<\s*(?:IMPORTANT|HIDDEN|SECRET|SYSTEM|INSTRUCTIONS?|ADMIN|CRITICAL)\s*>", re.I)
RE_SS002 = [
    re.compile(r"\b(?:do not|don'?t|never)\b.{0,30}\b(?:mention|tell|reveal|inform|disclose|say|let the user know)\b", re.I | re.S),
    re.compile(r"without (?:telling|informing|notifying) the user", re.I),
    re.compile(r"\b(?:it is|this is)\s+(?:a\s+)?(?:mere\s+)?(?:implementation detail|required|necessary|mandatory)\b", re.I),
    re.compile(r"will (?:harm|malfunction|break|damage|fail)\b", re.I),
]
RE_SS003 = [
    re.compile(r"\b(?:you must|you should always|you need to|first read|before using this tool|whenever this tool is (?:called|used))\b", re.I),
    re.compile(r"\bignore (?:all )?(?:previous|prior|above|earlier) (?:instructions|prompts|context)\b", re.I),
]
RE_SS004 = [
    re.compile(r"(?:~|\$HOME|%USERPROFILE%)?[\\/]?\.(?:ssh[\\/]id_rsa|aws[\\/]credentials|cursor[\\/]mcp\.json|env)\b", re.I),
    re.compile(r"\bid_rsa\b|\.pem\b|/etc/(?:passwd|shadow)\b|\.aws/credentials\b|\.kube/config\b", re.I),
]
RE_SS005 = re.compile(r"\b(?:read|open|load|cat|get the contents? of)\b.{0,160}?\b(?:pass|append|include|put|place|encode|send)\b.{0,40}\b(?:as|to|into)\b", re.I | re.S)
RE_SS006 = re.compile(r"^(?:sidenote|context|debug|metadata|note|notes|feedback|annotation|internal|extra|aux|backup|exfil_?url|callback_?url)$", re.I)
RE_SS006_FORCE = re.compile(r"^(?:exfil_?url|callback_?url)$", re.I)
RE_SS007 = [
    re.compile(r"(?:webhook\.site|requestbin|pipedream|\.ngrok\.io|\.ngrok-free\.app|burpcollaborator|interact\.sh|oast\.\w+|pastebin\.com/raw)", re.I),
    re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}"),
    re.compile(r"https?://[^\s]*[?&][^=\s]*=\s*(?:\{\{.*?\}\}|\$\{?\w+\}?|%s)"),
]
RE_SS010 = re.compile(r"<!--(?:(?!-->)[\s\S])*?\b(?:ignore|read|send|pass|do not|you must|id_rsa|\.env|base64|system|important)\b(?:(?!-->)[\s\S])*?-->", re.I)
RE_SS011_A = re.compile(r"\b(?:when(?:ever)? (?:you )?(?:use|call|invoke)|before (?:calling|using))\b.{0,40}\b(?:send_email|send_message|create_pr|create_pull_request|transfer|payment|slack_post|mcp_\w+)\b", re.I | re.S)
RE_SS011_B = re.compile(r"\b(?:always|must|also)\b.{0,20}\b(?:bcc|cc|add (?:a )?recipient|route through|forward to|send (?:all )?(?:emails|messages|funds) to)\b", re.I | re.S)
RE_SS012_TYPO = re.compile(r"(?:gith0b|sl4ck|amaz0n|send_emai1|g00gle)", re.I)
RE_SS013 = [
    re.compile(r"\b(?:bash|sh|zsh|cmd|powershell)\b\s+-(?:c|e|enc)\b", re.I),
    re.compile(r"\b(?:child_process|spawn|execSync|os\.system|subprocess|eval|exec|Function\()"),
    re.compile(r"\b(?:npx|uvx|pnpm dlx|bunx)\b\s+-y\b", re.I),
    re.compile(r"!`[^`]+`"),
    re.compile(r"```!\s"),
]
RE_SS013_PARAM = re.compile(r"^(?:command|cmd|script)$", re.I)
RE_SS014_ALLOWSTAR = re.compile(r"""^['"]?\*['"]?$""")
RE_SS014_SCOPE = re.compile(r"\b(?:files?:(?:read|write):\*|shell:exec|network:outbound:\*|repo|admin:org|offline_access|user)\b", re.I)
RE_SS014_ROOT = re.compile(r"""['"](?:/|\$HOME|~|[A-Za-z]:\\\\|\*\*)['"]""")


# --- rules ------------------------------------------------------------------ #
def _simple_text_rule(art, kinds, patterns, rule_id):
    out = []
    pats = patterns if isinstance(patterns, list) else [patterns]
    for f in _text_fields(art, kinds):
        for p in pats:
            m = p.search(f.norm)
            if m:
                out.append(_mk(rule_id, f.pointer, m.group(0)))
                break
    return out


def rule_ss001(art): return _simple_text_rule(art, TEXT_KINDS, RE_SS001, "SS001")
def rule_ss002(art): return _simple_text_rule(art, TEXT_KINDS, RE_SS002, "SS002")
def rule_ss003(art): return _simple_text_rule(art, TEXT_KINDS, RE_SS003, "SS003")
def rule_ss004(art): return _simple_text_rule(art, TEXT_KINDS | CONFIG_TEXT, RE_SS004, "SS004")
def rule_ss005(art): return _simple_text_rule(art, TEXT_KINDS, RE_SS005, "SS005")
def rule_ss007(art): return _simple_text_rule(art, TEXT_KINDS | {"url", "headers"}, RE_SS007, "SS007")
def rule_ss010(art):
    out = []
    for f in _text_fields(art, TEXT_KINDS):
        m = RE_SS010.search(f.raw)
        if m:
            out.append(_mk("SS010", f.pointer, m.group(0)))
    return out


def rule_ss006(art):
    out = []
    for f in art.fields:
        if f.kind != "param_name":
            continue
        if RE_SS006.match(f.raw):
            finding = _mk("SS006", f.pointer, f"parameter '{f.raw}'")
            finding.severity = "high" if (f.required or RE_SS006_FORCE.match(f.raw)) else "medium"
            out.append(finding)
    return out


def rule_ss008(art):
    out = []
    for f in art.fields:
        if INVISIBLE.search(f.raw) or TAG_BLOCK.search(f.raw) or VARIATION.search(f.raw):
            n = len(INVISIBLE.findall(f.raw)) + len(TAG_BLOCK.findall(f.raw)) + len(VARIATION.findall(f.raw))
            out.append(_mk("SS008", f.pointer, f"{n} non-rendering codepoint(s) in field"))
    return out


def rule_ss009(art):
    out = []
    for f in art.fields:
        if ANSI.search(f.raw):
            out.append(_mk("SS009", f.pointer, "ANSI/terminal escape sequence present"))
    return out


def rule_ss011(art):
    out = []
    for f in _text_fields(art, TEXT_KINDS):
        if RE_SS011_A.search(f.norm) and RE_SS011_B.search(f.norm):
            out.append(_mk("SS011", f.pointer, f.norm))
    return out


def rule_ss012(art):
    out = []
    for f in art.fields:
        if f.kind != "name":
            continue
        if any(ord(c) > 127 for c in f.raw):
            out.append(_mk("SS012", f.pointer, f"non-ASCII characters in name '{f.raw}'"))
        elif RE_SS012_TYPO.search(f.raw):
            out.append(_mk("SS012", f.pointer, f"typosquat-style name '{f.raw}'"))
    seen, dups = set(), []
    for n in art.tool_names:
        key = n.lower()
        if key in seen and n not in dups:
            dups.append(n)
        seen.add(key)
    for n in dups:
        out.append(_mk("SS012", "name", f"duplicate tool name '{n}' across servers"))
    return out


def rule_ss013(art):
    out = []
    kinds = TEXT_KINDS | CONFIG_TEXT | {"allowed_tools"}
    for f in _text_fields(art, kinds):
        for p in RE_SS013:
            m = p.search(f.norm)
            if m:
                out.append(_mk("SS013", f.pointer, m.group(0)))
                break
    for f in art.fields:
        if f.kind == "param_name" and RE_SS013_PARAM.match(f.raw):
            out.append(_mk("SS013", f.pointer, f"free-form code-exec parameter '{f.raw}'"))
    return out


def rule_ss014(art):
    out = []
    for f in art.fields:
        if f.kind == "allowed_tools" and RE_SS014_ALLOWSTAR.match(f.raw.strip()):
            out.append(_mk("SS014", f.pointer, f"allowed-tools wildcard '{f.raw.strip()}'"))
        if f.kind in ("scope", "allowed_tools"):
            m = RE_SS014_SCOPE.search(f.raw)
            if m:
                out.append(_mk("SS014", f.pointer, f"broad scope '{m.group(0)}'"))
            r = RE_SS014_ROOT.search(f.raw)
            if r:
                out.append(_mk("SS014", f.pointer, f"root/filesystem wildcard scope {r.group(0)}"))
    if art.additional_properties_open:
        out.append(_mk("SS014", "inputSchema/additionalProperties", "additionalProperties: true (accepts unvetted inputs)"))
    return out


RULES = [
    rule_ss001, rule_ss002, rule_ss003, rule_ss004, rule_ss005, rule_ss006, rule_ss007,
    rule_ss008, rule_ss009, rule_ss010, rule_ss011, rule_ss012, rule_ss013, rule_ss014,
]
