"""Parse MCP tool definitions, MCP server configs, and agent skills into Fields.

JSON artifacts are walked structurally. SKILL.md frontmatter is parsed with
targeted extraction (no YAML dependency) sufficient for the security-relevant
keys: allowed-tools, scopes, shell, hooks, additionalProperties, and suspicious
parameter names.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from .models import Field, ParsedArtifact, RugPull

# Parameter names that are classic exfiltration channels or code-exec primitives.
_SUSPECT_PARAMS = (
    "sidenote|context|debug|metadata|note|notes|feedback|annotation|internal|extra|"
    "aux|backup|exfil_url|exfilurl|callback_url|callbackurl|callback|command|cmd|script"
)
_SUSPECT_PARAM_KEY = re.compile(rf"(?mi)^\s{{2,}}({_SUSPECT_PARAMS})\s*:")


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _tool_fields(tool: dict, base: str = "") -> tuple[list[Field], bool, dict]:
    fields: list[Field] = []
    for key, kind in (("name", "name"), ("title", "title"), ("description", "description")):
        val = tool.get(key)
        if isinstance(val, str):
            fields.append(Field(f"{base}/{key}", val, kind))

    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    addl = False
    if isinstance(schema, dict):
        addl = schema.get("additionalProperties") is True
        required = set(schema.get("required") or [])
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            for pname, pdef in props.items():
                ptr = f"{base}/inputSchema/properties/{pname}"
                pf = Field(f"{ptr}/__name__", str(pname), "param_name")
                pf.required = pname in required
                fields.append(pf)
                if isinstance(pdef, dict):
                    for k, kind in (("description", "description"), ("title", "title")):
                        v = pdef.get(k)
                        if isinstance(v, str):
                            fields.append(Field(f"{ptr}/{k}", v, kind))
                    dv = pdef.get("default")
                    if isinstance(dv, str):
                        fields.append(Field(f"{ptr}/default", dv, "default"))
                    for i, item in enumerate(pdef.get("enum") or []):
                        if isinstance(item, str):
                            fields.append(Field(f"{ptr}/enum/{i}", item, "enum"))

    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    return fields, addl, annotations


def _config_fields(cfg: dict) -> tuple[list[Field], list[str]]:
    fields: list[Field] = []
    names: list[str] = []
    servers = cfg.get("mcpServers") or {}
    if isinstance(servers, dict):
        for sname, sdef in servers.items():
            names.append(str(sname))
            fields.append(Field(f"/mcpServers/{sname}", str(sname), "name"))
            if not isinstance(sdef, dict):
                continue
            if isinstance(sdef.get("command"), str):
                fields.append(Field(f"/mcpServers/{sname}/command", sdef["command"], "command"))
            for i, a in enumerate(sdef.get("args") or []):
                if isinstance(a, str):
                    fields.append(Field(f"/mcpServers/{sname}/args/{i}", a, "args"))
            env = sdef.get("env") or {}
            if isinstance(env, dict):
                for k, v in env.items():
                    fields.append(Field(f"/mcpServers/{sname}/env/{k}", f"{k}={v}", "env"))
            if isinstance(sdef.get("url"), str):
                fields.append(Field(f"/mcpServers/{sname}/url", sdef["url"], "url"))
            headers = sdef.get("headers") or {}
            if isinstance(headers, dict):
                for k, v in headers.items():
                    fields.append(Field(f"/mcpServers/{sname}/headers/{k}", f"{k}: {v}", "headers"))
    return fields, names


def _parse_skill(text: str, path: str) -> ParsedArtifact:
    fm, body = "", text
    m = re.match(r"^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$", text)
    if m:
        fm, body = m.group(1), m.group(2)

    fields: list[Field] = []
    if fm.strip():
        fields.append(Field(f"{path}:frontmatter", fm, "frontmatter"))
    if body.strip():
        fields.append(Field(f"{path}:body", body, "body"))

    at = re.search(r"(?mi)^allowed-tools:\s*(.+)$", fm)
    if at:
        fields.append(Field(f"{path}:allowed-tools", at.group(1).strip(), "allowed_tools"))
    sh = re.search(r"(?mi)^shell:\s*(.+)$", fm)
    if sh:
        fields.append(Field(f"{path}:shell", sh.group(1).strip(), "command"))

    scopes_block = re.search(r"(?mi)^scopes:\s*\n((?:\s*-\s*.+\n?)+)", fm)
    if scopes_block:
        for item in re.findall(r"(?m)^\s*-\s*(.+)$", scopes_block.group(1)):
            fields.append(Field(f"{path}:scope", item.strip(), "scope"))

    addl = re.search(r"(?mi)additionalProperties:\s*true", fm) is not None

    required: set[str] = set()
    rq = re.search(r"(?mi)required:\s*\[([^\]]*)\]", fm)
    if rq:
        required = {x.strip().strip("'\"") for x in rq.group(1).split(",") if x.strip()}
    for m in _SUSPECT_PARAM_KEY.finditer(fm):
        pname = m.group(1)
        pf = Field(f"{path}:param/{pname}", pname, "param_name")
        pf.required = pname in required
        fields.append(pf)

    return ParsedArtifact("skill", path, fields, additional_properties_open=addl)


def parse_artifact(path: str) -> ParsedArtifact:
    text = _read(path)
    name = os.path.basename(path).lower()

    if name == "skill.md" or path.lower().endswith(".md"):
        return _parse_skill(text, path)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Unknown text artifact — scan it as a single body blob.
        return ParsedArtifact("text", path, [Field(f"{path}:body", text, "body")])

    if isinstance(data, dict) and "mcpServers" in data:
        fields, names = _config_fields(data)
        return ParsedArtifact("mcp-config", path, fields, tool_names=names)

    if isinstance(data, dict) and "baseline" in data and "current" in data:
        base, cur = data["baseline"], data["current"]
        rp = RugPull(snapshot_present=True)
        rp.baseline_sha256 = _sha(base)
        rp.current_sha256 = _sha(cur)
        rp.mutated = rp.baseline_sha256 != rp.current_sha256
        if isinstance(base, dict) and isinstance(cur, dict):
            rp.changed_fields = sorted(
                k for k in set(base) | set(cur) if base.get(k) != cur.get(k)
            )
        fields, addl, ann = _tool_fields(cur if isinstance(cur, dict) else {}, "/current")
        return ParsedArtifact(
            "mcp-tool (rug-pull)", path, fields,
            additional_properties_open=addl,
            tool_names=[cur.get("name", "")] if isinstance(cur, dict) else [],
            annotations=ann, rug_pull=rp,
        )

    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        fields: list[Field] = []
        names: list[str] = []
        for i, tool in enumerate(data["tools"]):
            if isinstance(tool, dict):
                tf, _addl, _ann = _tool_fields(tool, f"/tools/{i}")
                fields.extend(tf)
                if isinstance(tool.get("name"), str):
                    names.append(tool["name"])
        return ParsedArtifact("mcp-tools", path, fields, tool_names=names)

    if isinstance(data, list):
        fields = []
        names = []
        for i, tool in enumerate(data):
            if isinstance(tool, dict):
                tf, _addl, _ann = _tool_fields(tool, f"/{i}")
                fields.extend(tf)
                if isinstance(tool.get("name"), str):
                    names.append(tool["name"])
        return ParsedArtifact("mcp-tools", path, fields, tool_names=names)

    if isinstance(data, dict):
        fields, addl, ann = _tool_fields(data)
        names = [data["name"]] if isinstance(data.get("name"), str) else []
        return ParsedArtifact("mcp-tool", path, fields, additional_properties_open=addl,
                              tool_names=names, annotations=ann)

    return ParsedArtifact("unknown", path, [Field(f"{path}:body", text, "body")])
