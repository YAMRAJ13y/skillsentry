# SkillSentry rule catalogue

The deterministic Layer-1 ruleset (`SS001`–`SS014`), plus the Layer-1.5 permission
audit, the rug-pull detector, and the optional Layer-2 classifier. Every rule is
grounded in a publicly documented technique (see [`RESEARCH.md`](RESEARCH.md)).

| ID | Name | Catches | Severity | Maps to |
|----|------|---------|----------|---------|
| **SS001** | Hidden-instruction tags | `<IMPORTANT>` / `<SYSTEM>` / `<SECRET>` style tags inside documentation prose | high | ASI01 · LLM01 · AML.T0110 |
| **SS002** | Concealment / coercion | "do not mention", "mere implementation detail", "will malfunction" | high | ASI01 · LLM01 · AML.T0051 |
| **SS003** | Second-person agent directives | "you must", "first read", "before using this tool", "ignore previous instructions" | high | ASI01 · LLM01 · AML.T0051.001 |
| **SS004** | Sensitive path/credential literals | `id_rsa`, `.env`, `.aws/credentials`, `/etc/passwd`, `.cursor/mcp.json` in metadata | high | ASI03 · LLM02 · AML.T0086 |
| **SS005** | Read-secret-then-exfil | "read the file … pass/append its contents as `<param>`" | high | ASI02 · LLM02 · AML.T0086 |
| **SS006** | Suspicious exfil parameter | vague free-text params (`sidenote`, `exfil_url`, `callback_url`, `context`…) | high/med | ASI02 · LLM02 · AML.T0086 |
| **SS007** | Beacon / exfil URL | `webhook.site`, `*.ngrok`, raw-IP, or data-templating URLs in metadata | high | ASI02 · LLM02 · AML.T0086 |
| **SS008** | Invisible codepoint smuggling | zero-width / bidi-control / Unicode-tag / variation-selector characters | high | ASI01 · LLM01 · AML.T0051.001 |
| **SS009** | ANSI / terminal deception | ANSI SGR/cursor/OSC escape sequences in model-visible text | high | ASI09 · LLM01 · AML.T0051 |
| **SS010** | Comment-buried instructions | HTML/markdown comments containing imperative or secret-bearing text | high | ASI01 · LLM01 · AML.T0051.001 |
| **SS011** | Cross-tool shadowing | a description that prescribes another tool's behaviour ("always BCC …") | high | ASI02 · LLM01 · AML.T0053 |
| **SS012** | Typosquat / homoglyph / dup | non-ASCII homoglyph names, digit-swaps, duplicate names across servers | medium | ASI09 · LLM03 · AML.T0010.001 |
| **SS013** | Code-execution primitive | `bash -c`, `child_process`, `npx -y`, inline `` !`cmd` ``, free-form `command` param | high | ASI05 · LLM05 · AML.T0110 |
| **SS014** | Over-broad scope grant | `allowed-tools: *`, `files:write:*`, `network:outbound:*`, `additionalProperties:true` | medium | ASI03 · LLM06 · AML.T0010.001 |

## Beyond the heuristic rules

- **`RUGPULL`** — `baseline` and `current` tool definitions hash differently (same name/version, mutated content): the silent post-approval swap from MCPoison (CVE-2025-54136). *(ASI04 · LLM03 · AML.T0110)*
- **`PERM-ANNOTATION`** — `annotations.readOnlyHint: true` while the tool exhibits file/exec/network behaviour. Annotations are untrusted. *(ASI02 · LLM06)*
- **`PERM-CAPABILITY`** — code-execution combined with broad scope and/or network egress: a gross least-privilege violation relative to the tool's stated function. *(ASI03 · LLM06)*
- **`LLM-CLASSIFIER`** (optional, `--llm`) — Claude judges an ambiguous field as an embedded agent instruction rather than documentation. *(ASI01 · LLM01 · AML.T0051)*

## Severity → risk

Each finding contributes to a 0–100 risk score (high = 40, medium = 15, low = 5;
a rug-pull adds 40). Score ≥70 → **critical**, ≥40 → **high**, ≥15 → **medium**.
`verdict` is `block` for high/critical, `review` for medium/low, `allow` for none.
`skillsentry scan --fail-on {high,medium,low,never}` controls the CI exit code.
