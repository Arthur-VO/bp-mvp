from typing import Any

from pydantic import BaseModel


class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: dict[str, Any] = {}


class MCPPrompt(BaseModel):
    name: str
    description: str | None = None


class MCPResource(BaseModel):
    uri: str
    name: str | None = None
    mimeType: str | None = None
