import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from models import MCPPrompt, MCPResource, MCPTool
from sast import Finding, run_sast


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


def run_discovery(target_base_url: str) -> tuple[list[MCPTool], list[MCPPrompt], list[MCPResource], str]:
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

    tools = [MCPTool.model_validate(item) for item in tools_raw]
    prompts = [MCPPrompt.model_validate(item) for item in prompts_raw]
    resources = [MCPResource.model_validate(item) for item in resources_raw]

    return tools, prompts, resources, sse_status


def _severity_order(finding: Finding) -> int:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return order.get(finding.severity.value, 99)


def write_reports(
    target_base_url: str,
    tools: list[MCPTool],
    prompts: list[MCPPrompt],
    resources: list[MCPResource],
    sse_status: str,
    sast_findings: list[Finding],
    fuzz_findings: list[Finding],
    output_dir: Path,
) -> dict[str, Any]:
    sast_sorted = sorted(sast_findings, key=_severity_order)
    fuzz_sorted = sorted(fuzz_findings, key=_severity_order)

    def _section(findings: list[Finding]) -> dict[str, Any]:
        return {
            "finding_count": len(findings),
            "high": sum(1 for f in findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity.value == "LOW"),
            "findings": [f.model_dump() for f in findings],
        }

    report: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_base_url,
        "discovery": {
            "sse": sse_status,
            "tool_count": len(tools),
            "prompt_count": len(prompts),
            "resource_count": len(resources),
            "tools": [t.model_dump() for t in tools],
            "prompts": [p.model_dump() for p in prompts],
            "resources": [r.model_dump() for r in resources],
        },
        "sast": _section(sast_sorted),
        "fuzzing": _section(fuzz_sorted),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    _write_markdown(report, tools, prompts, resources, sast_sorted, fuzz_sorted, md_path)

    return report


def _findings_block(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["Geen bevindingen."]
    lines: list[str] = []
    badge_map = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}
    for f in findings:
        badge = badge_map.get(f.severity.value, "")
        lines += [
            f"### {badge} [{f.rule_id}] {f.title}",
            "",
            f"- **Severity**: {f.severity.value}",
            f"- **Tool**: `{f.tool_name}`",
            f"- **Detail**: {f.detail}",
            "",
        ]
    return lines


def _write_markdown(
    report: dict[str, Any],
    tools: list[MCPTool],
    prompts: list[MCPPrompt],
    resources: list[MCPResource],
    sast_findings: list[Finding],
    fuzz_findings: list[Finding],
    md_path: Path,
) -> None:
    sast = report["sast"]
    fuzzing = report["fuzzing"]

    lines: list[str] = [
        "# MCP Security Assessment Report",
        "",
        f"- **Timestamp**: {report['timestamp']}",
        f"- **Target**: {report['target']}",
        f"- **SSE status**: {report['discovery']['sse']}",
        "",
        "## Discovery",
        "",
        "| Type | Count |",
        "|------|-------|",
        f"| Tools | {len(tools)} |",
        f"| Prompts | {len(prompts)} |",
        f"| Resources | {len(resources)} |",
        "",
        "### Tools",
    ]

    for tool in tools:
        lines.append(f"- `{tool.name}`: {tool.description}")

    lines += ["", "### Prompts"]
    for prompt in prompts:
        lines.append(f"- `{prompt.name}`: {prompt.description or 'n/a'}")

    lines += ["", "### Resources"]
    for resource in resources:
        lines.append(f"- `{resource.name or resource.uri}` ({resource.uri})")

    lines += [
        "",
        "---",
        "",
        "## SAST Findings",
        "",
        f"**{sast['finding_count']} bevindingen** — "
        f"HIGH: {sast['high']} | MEDIUM: {sast['medium']} | LOW: {sast['low']}",
        "",
    ]
    lines.extend(_findings_block(sast_findings))

    lines += [
        "---",
        "",
        "## Fuzzing Findings",
        "",
        f"**{fuzzing['finding_count']} bevindingen** — "
        f"HIGH: {fuzzing['high']} | MEDIUM: {fuzzing['medium']} | LOW: {fuzzing['low']}",
        "",
    ]
    lines.extend(_findings_block(fuzz_findings))

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    target = os.getenv("TARGET_MCP_URL", "http://localhost:8080/sse")
    target_base = target.removesuffix("/sse") if target.endswith("/sse") else target
    output_dir = Path(os.getenv("REPORT_DIR", "/app/reports"))

    print(f"[scanner] Starting discovery against {target_base}")
    tools, prompts, resources, sse_status = run_discovery(target_base)
    print(
        f"[scanner] Discovery done — tools={len(tools)} prompts={len(prompts)} resources={len(resources)}"
    )

    print("[scanner] Running SAST analysis...")
    sast_findings = run_sast(tools)
    print(f"[scanner] SAST done — {len(sast_findings)} finding(s)")

    print("[scanner] Running fuzzing analysis...")
    from fuzzer import run_fuzzing
    rpc_url = f"{target_base.rstrip('/')}/rpc"
    fuzz_findings = run_fuzzing(rpc_url, tools)
    print(f"[scanner] Fuzzing done — {len(fuzz_findings)} finding(s)")

    report = write_reports(target_base, tools, prompts, resources, sse_status, sast_findings, fuzz_findings, output_dir)

    sast = report["sast"]
    fuzzing = report["fuzzing"]
    print(
        f"[scanner] SAST — HIGH={sast['high']} MEDIUM={sast['medium']} LOW={sast['low']} | "
        f"FUZZ — HIGH={fuzzing['high']} MEDIUM={fuzzing['medium']} LOW={fuzzing['low']} | "
        f"Reports written to {output_dir}"
    )


if __name__ == "__main__":
    main()
