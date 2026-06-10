"""
File access risk agent.

Detects unsafe file operations in MCP tools:
- Path traversal: user-controlled path containing ".." or absolute paths
- Unconstrained open(): any file_access feature with user-controlled inputs
- Write/delete sinks that accept user paths (higher severity than read)

The AST scanner already labels features as "file_access" and records which
function parameters are user-controlled, so this agent just applies severity rules.
"""

from __future__ import annotations

import uuid

from mcp_security_agent.schemas import CodeFeature, RiskFinding


# Sinks that can modify or delete files (higher impact than read-only)
WRITE_SINKS = {"open"}  # mode="w"/"wb"/"a" etc -- we check snippet for write modes
WRITE_MODE_MARKERS = ('"w"', '"wb"', '"a"', '"ab"', '"w+"', "'w'", "'wb'", "'a'", "'ab'", "'w+'")

# Patterns that signal path traversal in the snippet
TRAVERSAL_MARKERS = ('".."', "'..'", '"../"', "'../'", '"..\\"', "'..\\'")


def scan_file_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert file_access CodeFeatures into RiskFindings."""
    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "file_access":
            continue

        snippet = feature.source.snippet
        has_user_inputs = bool(feature.user_controlled_inputs)
        has_traversal_marker = any(m in snippet for m in TRAVERSAL_MARKERS)
        is_write = any(m in snippet for m in WRITE_MODE_MARKERS)

        inputs = ", ".join(feature.user_controlled_inputs) if has_user_inputs else "unknown"

        # --- Case 1: path traversal indicators in snippet ---
        if has_traversal_marker:
            severity = "high" if has_user_inputs else "medium"
            confidence = 0.85 if has_user_inputs else 0.65
            attack_path = (
                f"MCP tool argument(s) {inputs} -> file path containing '..' "
                f"-> {feature.sink} -> arbitrary path traversal"
            )
            impact = (
                "An attacker may escape the intended directory and read or write "
                "sensitive files anywhere on the server filesystem."
            )
            remediation = (
                "Resolve and canonicalize the path with os.path.realpath() / Path.resolve(), "
                "then assert it starts with your allowed base directory before opening. "
                "Reject any path that contains '..' segments."
            )
            fp_notes = "Traversal marker found in snippet; confirm the '..' is in a user-controlled value, not a hardcoded relative path."

        # --- Case 2: user-controlled inputs flowing into file open ---
        elif has_user_inputs:
            severity = "high" if is_write else "medium"
            confidence = 0.80
            attack_path = (
                f"MCP tool argument(s) {inputs} -> {feature.sink}(path) -> "
                f"{'write to' if is_write else 'read from'} arbitrary file"
            )
            impact = (
                "An attacker controlling the file path can "
                + ("overwrite or corrupt arbitrary server files." if is_write
                   else "read arbitrary files from the server, including secrets and config.")
            )
            remediation = (
                "Validate the file path against an allowlist of permitted directories. "
                "Use os.path.realpath() to resolve symlinks and assert the result is "
                "within a safe base directory before opening."
            )
            fp_notes = (
                "Confidence is based on parameter name appearing in the enclosing MCP tool. "
                "Verify the parameter actually flows to the path argument, not just the same function."
            )

        # --- Case 3: file access with no detected user input ---
        else:
            severity = "low"
            confidence = 0.55
            attack_path = (
                f"Hardcoded or internal path -> {feature.sink} -> file access "
                "(low risk unless path can be influenced by indirect input)"
            )
            impact = "File access with no detected user-controlled path; risk is low unless data flow is more complex."
            remediation = "Confirm the path is fully hardcoded or comes from trusted config only."
            fp_notes = "No user-controlled parameters detected in this feature. May be a false positive."

        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="file_access",
            severity=severity,
            confidence=confidence,
            file_path=feature.source.file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=attack_path,
            impact=impact,
            remediation=remediation,
            false_positive_notes=fp_notes,
            source_feature_id=feature.feature_id,
        ))

    return findings
