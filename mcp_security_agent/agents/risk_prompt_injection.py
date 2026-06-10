"""
Prompt injection risk agent.

Detects cases where MCP tool arguments are interpolated into prompt-like strings,
creating a path for model-controlled or user-controlled input to hijack LLM behavior.

Strategy:
- Pair mcp_tool features (which list user-controlled parameter names) with
  prompt_construction features in the same file.
- If a prompt_construction feature's snippet references one of the tool's params,
  flag it as high-severity prompt injection.
- Standalone prompt_construction features with no tool context get medium severity
  (the risk exists but traceability is weaker).
"""

from __future__ import annotations

import re
import uuid

from mcp_security_agent.schemas import CodeFeature, RiskFinding


def scan_prompt_injection_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert prompt_construction + mcp_tool CodeFeatures into RiskFindings."""

    # Index mcp_tool features by file so we can look up which params are user-controlled
    # key: file_path -> list of (tool_name, user_controlled_inputs, line_start)
    tool_index: dict[str, list[tuple[str, list[str], int]]] = {}
    for f in features:
        if f.feature_type == "mcp_tool":
            tool_index.setdefault(f.source.file_path, []).append(
                (f.sink, f.user_controlled_inputs, f.source.line_start)
            )

    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "prompt_construction":
            continue

        snippet = feature.source.snippet
        file_path = feature.source.file_path

        # Look for mcp_tool in the same file whose params appear in the snippet
        controlled_params: list[str] = []
        tool_name = ""
        for (t_name, t_inputs, _) in tool_index.get(file_path, []):
            for param in t_inputs:
                # param name appears in the interpolated snippet -> taint flow
                if _param_in_snippet(param, snippet):
                    controlled_params.append(param)
                    tool_name = t_name

        if controlled_params:
            severity = "high"
            confidence = 0.85
            attack_path = (
                f"MCP tool '{tool_name}' parameter(s) {controlled_params} "
                f"-> interpolated into prompt string -> LLM instruction injection"
            )
            impact = (
                "An attacker controlling the tool argument can embed instructions "
                "that override the system prompt, exfiltrate context, or cause the "
                "model to take unintended actions."
            )
            remediation = (
                "Never interpolate raw tool arguments into prompts. "
                "Sanitize or allowlist inputs before constructing the prompt, "
                "or use a separate untrusted-data section clearly delimited from instructions."
            )
            fp_notes = (
                "Rule fires when a tool param name appears verbatim in the f-string snippet. "
                "May miss renamed variables or multi-step flows; may false-positive on "
                "same-named variables that are not actually the tool param."
            )
        else:
            # Prompt construction without a clearly tainted source -- lower confidence
            severity = "medium"
            confidence = 0.60
            attack_path = (
                "Dynamic string construction -> prompt passed to LLM -> "
                "potential instruction injection if any upstream input is attacker-controlled"
            )
            impact = (
                "If the interpolated values derive from user or model input, "
                "the prompt can be hijacked to override instructions."
            )
            remediation = (
                "Audit all variables interpolated into this prompt. "
                "Ensure none derive from untrusted sources without sanitization."
            )
            fp_notes = (
                "No direct MCP tool parameter taint detected. "
                "Risk is conditional on whether interpolated values are user-controlled."
            )

        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="prompt_injection",
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=attack_path,
            impact=impact,
            remediation=remediation,
            false_positive_notes=fp_notes,
            source_feature_id=feature.feature_id,
        ))

    return findings


def _param_in_snippet(param: str, snippet: str) -> bool:
    """
    Check if a parameter name appears in a code snippet as a standalone identifier.
    Covers {param}, f'{param}', and plain variable references.
    """
    pattern = r'(?<![a-zA-Z0-9_])' + re.escape(param) + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, snippet))
