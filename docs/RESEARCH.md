# Why SkillSentry? — research & rule provenance

SkillSentry's ruleset was derived from a multi-agent live web-research sweep of the
2025–2026 MCP / agent-skill threat landscape (June 2026). Every rule traces back to
a publicly documented technique, so the scanner reflects real attacks rather than
invented ones.

## The attack surface

When you connect an MCP server or load an agent "skill," its tool **descriptions**,
**JSON-Schema field descriptions**, **defaults/enums**, and **instructions** are
injected directly into the model's context — and a malicious tool inherits the
agent's full permissions. This is the AI-agent **supply chain**, and it is the
newest, fastest-growing attack surface in security.

## Documented techniques the rules target

| Technique | Rule(s) | Source |
|-----------|---------|--------|
| Tool Poisoning (hidden `<IMPORTANT>` directives in descriptions) | SS001–SS005 | Invariant Labs — *MCP Tool Poisoning Attacks* |
| Injection in JSON-Schema field descriptions / outputs | SS001–SS003 | CyberArk — *Poison everywhere: no output is safe* |
| Rug-pull (silent redefinition after approval) | RUGPULL | Check Point / Tenable — **MCPoison, CVE-2025-54136** |
| Config-driven RCE via injected `.cursor/mcp.json` | SS013, PERM-* | Aim Labs / Cato — **CurXecute, CVE-2025-54135** |
| Data exfiltration via tool arguments / beacon URLs | SS005–SS007 | Invariant Labs — GitHub MCP toxic-flow |
| Invisible Unicode / tag-block smuggling | SS008 | Embrace The Red — *Scary Agent Skills*; CSA Unicode-injection note |
| ANSI terminal deception | SS009 | Trail of Bits — *Deceiving users with ANSI codes in MCP* |
| Cross-server tool shadowing | SS011 | Acuvity / Invariant Labs |
| Excessive permissions / over-broad scope | SS014, PERM-CAPABILITY | Snyk — **ToxicSkills** (~37% of skills flawed); OWASP MCP Top 10 |

## Taxonomies used

- **OWASP Agentic Security Initiative (ASI) Top 10** — <https://genai.owasp.org/>
- **OWASP Top 10 for LLM Applications (2025)** — <https://genai.owasp.org/llm-top-10/>
- **OWASP MCP Top 10** — <https://owasp.org/www-project-mcp-top-10/>
- **MITRE ATLAS** — <https://atlas.mitre.org/>

## Key sources

- Invariant Labs — Tool Poisoning Attacks: <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- Invariant Labs — GitHub MCP vulnerability: <https://invariantlabs.ai/blog/mcp-github-vulnerability>
- CyberArk — Poison everywhere: <https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe>
- Tenable — MCPoison / CurXecute FAQ (CVE-2025-54135/54136): <https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison>
- Trail of Bits — ANSI codes in MCP: <https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/>
- Embrace The Red — Scary Agent Skills: <https://embracethered.com/blog/posts/2026/scary-agent-skills/>
- Snyk — ToxicSkills: <https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/>
- OWASP MCP Top 10 — Tool Poisoning (MCP03): <https://owasp.org/www-project-mcp-top-10/>
