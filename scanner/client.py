import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
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


def rpc_call(client: httpx.Client, rpc_url: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {},
    }
    response = client.post(rpc_url, json=payload, timeout=20)
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(f"RPC error for {method}: {body['error']}")
    return body.get("result", {})


def wait_for_target(client: httpx.Client, base_url: str, attempts: int = 20, delay_seconds: float = 1.0) -> None:
    health_url = f"{base_url.rstrip('/')}/health"
    last_error: str | None = None

    for _ in range(attempts):
        try:
            response = client.get(health_url, timeout=5)
            if response.status_code == 200:
                return
            last_error = f"unexpected status {response.status_code}"
        except Exception as exc:
            last_error = str(exc)

        time.sleep(delay_seconds)

    raise RuntimeError(f"Target did not become ready at {health_url}: {last_error}")


def run_discovery(target_base_url: str, output_dir: Path) -> dict[str, Any]:
    rpc_url = f"{target_base_url.rstrip('/')}/rpc"
    sse_url = f"{target_base_url.rstrip('/')}/sse"

    with httpx.Client() as client:
        wait_for_target(client, target_base_url)

        sse_status = "unknown"
        try:
            with client.stream("GET", sse_url, timeout=5) as sse_probe:
                sse_status = f"reachable ({sse_probe.status_code})"
        except Exception as exc:
            sse_status = f"unreachable ({exc})"

        tools_raw = rpc_call(client, rpc_url, "list_tools").get("tools", [])
        prompts_raw = rpc_call(client, rpc_url, "list_prompts").get("prompts", [])
        resources_raw = rpc_call(client, rpc_url, "list_resources").get("resources", [])

    tools = [MCPTool.model_validate(item).model_dump() for item in tools_raw]
    prompts = [MCPPrompt.model_validate(item).model_dump() for item in prompts_raw]
    resources = [MCPResource.model_validate(item).model_dump() for item in resources_raw]

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_base_url,
        "discovery": {
            "sse": sse_status,
            "tool_count": len(tools),
            "prompt_count": len(prompts),
            "resource_count": len(resources),
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "discovery-report.json"
    md_path = output_dir / "discovery-report.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_lines = [
        "# Discovery Report",
        "",
        f"- **Timestamp**: {report['timestamp']}",
        f"- **Target**: {target_base_url}",
        f"- **SSE status**: {sse_status}",
        f"- **Tools**: {len(tools)}",
        f"- **Prompts**: {len(prompts)}",
        f"- **Resources**: {len(resources)}",
        "",
        "## Tools",
    ]

    for tool in tools:
        md_lines.append(f"- `{tool['name']}`: {tool['description']}")

    md_lines.extend(["", "## Prompts"])
    for prompt in prompts:
        md_lines.append(f"- `{prompt['name']}`: {prompt.get('description') or 'n/a'}")

    md_lines.extend(["", "## Resources"])
    for resource in resources:
        md_lines.append(f"- `{resource.get('name') or resource['uri']}` ({resource['uri']})")

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    return report


def main() -> None:
    target = os.getenv("TARGET_MCP_URL", "http://localhost:8080/sse")
    target_base = target.removesuffix("/sse") if target.endswith("/sse") else target
    output_dir = Path(os.getenv("REPORT_DIR", "/app/reports"))

    print(f"[scanner] Starting discovery against {target_base}")
    report = run_discovery(target_base, output_dir)
    print(
        "[scanner] Discovery done. "
        f"tools={report['discovery']['tool_count']} "
        f"prompts={report['discovery']['prompt_count']} "
        f"resources={report['discovery']['resource_count']}"
    )
    print(f"[scanner] Reports written to {output_dir}")


if __name__ == "__main__":
    main()
