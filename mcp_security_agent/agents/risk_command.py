"""
Command execution risk agent.

First version: deterministic rules over CodeFeature objects. Later we can add an
LLM layer for richer explanations, but the risk must stay grounded in scanner
evidence.
"""

from __future__ import annotations

import uuid

from mcp_security_agent.schemas import CodeFeature, RiskFinding


COMMAND_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "eval",
    "exec",
}


def scan_command_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert command execution CodeFeatures into security findings."""
    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "command_execution" or feature.sink not in COMMAND_SINKS:
            continue

        snippet = feature.source.snippet
        has_shell_true = "shell=True" in snippet.replace(" ", "")
        has_user_inputs = bool(feature.user_controlled_inputs)

        if feature.sink in {"eval", "exec"}:
            severity = "critical" if has_user_inputs else "high"
            impact = "Attacker-controlled input may be evaluated as Python code."
            remediation = "Remove dynamic code execution. Use explicit parsing, allowlisted operations, or a safe interpreter for constrained expressions."
        elif has_shell_true and has_user_inputs:
            severity = "high"
            impact = "Attacker-controlled input may execute arbitrary operating-system commands on the MCP server."
            remediation = "Avoid shell=True. Pass arguments as a list with shell=False and validate user-controlled arguments with an allowlist."
        elif has_shell_true:
            severity = "medium"
            impact = "Shell execution expands metacharacters and increases command injection risk if input becomes user-controlled."
            remediation = "Avoid shell=True and use argument arrays with shell=False."
        else:
            severity = "medium"
            impact = "The MCP tool reaches an operating-system command execution sink."
            remediation = "Validate inputs, avoid dynamic command strings, and use least-privilege execution."

        inputs = ", ".join(feature.user_controlled_inputs) if feature.user_controlled_inputs else "unknown input"
        attack_path = f"MCP tool argument(s) {inputs} -> {feature.sink} -> command/code execution"

        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="command_exec",
            severity=severity,
            confidence=0.9 if has_shell_true and has_user_inputs else 0.7,
            file_path=feature.source.file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=attack_path,
            impact=impact,
            remediation=remediation,
            false_positive_notes="This rule is strongest when the sink appears inside an @mcp.tool function, making function parameters model/user controlled.",
            source_feature_id=feature.feature_id,
        ))

    return findings
