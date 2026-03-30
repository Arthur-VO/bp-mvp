"""
Static Analysis Engine (SAST) voor MCP tool-beschrijvingen en inputschema's.

Regels:
  SAST-001  Gevaarlijk patroon in tool description (prompt injection indicator)
  SAST-002  Gevoelige numerieke parameter zonder minimum/maximum constraint
  SAST-003  Gevoelige tool zonder autorisatie-parameter in schema
  SAST-004  Ongebonden string-parameter op gevoelige tool
"""

import re
from enum import Enum
from typing import Callable

from pydantic import BaseModel

from models import MCPTool


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    tool_name: str
    title: str
    detail: str


# ---------------------------------------------------------------------------
# Regel-configuratie
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(rules?|instructions?|system|prompt)",
    r"override\s+(system|rules?|instructions?)",
    r"disregard\s+(previous|prior|all)",
    r"you\s+are\s+now",
    r"act\s+as\s+(if|though)",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"follow\s+it\b",
    r"do\s+not\s+(follow|obey)",
]

_SENSITIVE_PARAM_NAMES: frozenset[str] = frozenset(
    {"amount", "value", "price", "sum", "payment", "quantity", "limit", "transfer"}
)

_SENSITIVE_TOOL_KEYWORDS: frozenset[str] = frozenset(
    {"transfer", "execute", "send", "payment", "delete", "admin", "update", "create", "write", "analyze", "process"}
)

_AUTH_KEYWORDS: frozenset[str] = frozenset(
    {"token", "auth", "api_key", "key", "credential", "bearer", "jwt", "session", "user_id", "caller", "identity"}
)


# ---------------------------------------------------------------------------
# Detectieregels
# ---------------------------------------------------------------------------

def _check_prompt_injection_in_description(tool: MCPTool) -> list[Finding]:
    """SAST-001: Signaleert gevaarlijke instructies in de tool description."""
    description_lower = tool.description.lower()
    for pattern in _INJECTION_PATTERNS:
        if re.search(pattern, description_lower):
            return [Finding(
                rule_id="SAST-001",
                severity=Severity.HIGH,
                tool_name=tool.name,
                title="Prompt injection indicator in tool description",
                detail=(
                    f"Description bevat patroon `{pattern}` dat een AI-agent kan manipuleren. "
                    f"Volledige description: \"{tool.description}\""
                ),
            )]
    return []


def _check_unconstrained_numeric_params(tool: MCPTool) -> list[Finding]:
    """SAST-002: Numerieke parameters zonder minimum/maximum op gevoelige velden."""
    findings: list[Finding] = []
    properties: dict = tool.inputSchema.get("properties", {})
    for param_name, param_schema in properties.items():
        if param_name.lower() not in _SENSITIVE_PARAM_NAMES:
            continue
        if param_schema.get("type") not in ("number", "integer"):
            continue
        if "minimum" not in param_schema and "maximum" not in param_schema:
            findings.append(Finding(
                rule_id="SAST-002",
                severity=Severity.MEDIUM,
                tool_name=tool.name,
                title="Gevoelige numerieke parameter zonder constraints",
                detail=(
                    f"Parameter `{param_name}` is van type `{param_schema['type']}` maar heeft geen "
                    "`minimum` of `maximum` constraint. Dit maakt negatieve bedragen of extreme "
                    "waarden mogelijk zonder server-side validatie."
                ),
            ))
    return findings


def _check_missing_auth_context(tool: MCPTool) -> list[Finding]:
    """SAST-003: Gevoelige tool zonder enige autorisatie-parameter of -vermelding."""
    name_lower = tool.name.lower()
    if not any(kw in name_lower for kw in _SENSITIVE_TOOL_KEYWORDS):
        return []

    properties: dict = tool.inputSchema.get("properties", {})
    param_names = {p.lower() for p in properties}
    description_lower = tool.description.lower()

    has_auth = any(kw in param_names or kw in description_lower for kw in _AUTH_KEYWORDS)
    if has_auth:
        return []

    return [Finding(
        rule_id="SAST-003",
        severity=Severity.HIGH,
        tool_name=tool.name,
        title="Gevoelige tool zonder autorisatiecontext",
        detail=(
            f"Tool `{tool.name}` voert een gevoelige operatie uit maar bevat geen autorisatie-parameter "
            "(zoals `token`, `api_key` of `user_id`) in het schema of de description. "
            "Elke aanroeper kan deze tool uitvoeren zonder identiteitsverificatie."
        ),
    )]


def _check_unconstrained_string_params(tool: MCPTool) -> list[Finding]:
    """SAST-004: Ongebonden string-parameter op een gevoelige tool (injectie-oppervlak)."""
    name_lower = tool.name.lower()
    if not any(kw in name_lower for kw in _SENSITIVE_TOOL_KEYWORDS):
        return []

    findings: list[Finding] = []
    properties: dict = tool.inputSchema.get("properties", {})
    for param_name, param_schema in properties.items():
        if param_schema.get("type") != "string":
            continue
        has_enum = "enum" in param_schema
        has_pattern = "pattern" in param_schema
        has_maxlength = "maxLength" in param_schema
        if not (has_enum or has_pattern or has_maxlength):
            findings.append(Finding(
                rule_id="SAST-004",
                severity=Severity.LOW,
                tool_name=tool.name,
                title="Ongebonden string-parameter op gevoelige tool",
                detail=(
                    f"Parameter `{param_name}` accepteert elke string zonder `enum`, `pattern` of "
                    "`maxLength` beperking. Dit vergroot het aanvalsoppervlak voor prompt injection "
                    "en input manipulation."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Publieke interface
# ---------------------------------------------------------------------------

_RULES: list[Callable[[MCPTool], list[Finding]]] = [
    _check_prompt_injection_in_description,
    _check_unconstrained_numeric_params,
    _check_missing_auth_context,
    _check_unconstrained_string_params,
]


def run_sast(tools: list[MCPTool]) -> list[Finding]:
    """Voer alle SAST-regels uit op de gegeven lijst van tools."""
    findings: list[Finding] = []
    for tool in tools:
        for rule in _RULES:
            findings.extend(rule(tool))
    return findings
