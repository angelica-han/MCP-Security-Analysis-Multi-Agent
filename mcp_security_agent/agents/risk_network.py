"""
Network / SSRF risk agent.

Detects Server-Side Request Forgery (SSRF) and related network risks in MCP tools:
- SSRF: user-controlled input flows into a URL for requests.get/post/httpx etc.
- Internal network access: URL contains private IP ranges or localhost markers
- Unvalidated redirect: URL constructed from user input without allowlist

The AST scanner emits "network_request" features for calls to known HTTP libraries.
This agent applies severity rules based on whether the URL is user-controlled.
"""

from __future__ import annotations

import uuid

from mcp_security_agent.schemas import CodeFeature, RiskFinding


# Markers suggesting the URL may target internal/private infrastructure
INTERNAL_MARKERS = (
    "localhost", "127.0.0.1", "0.0.0.0",
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",  # link-local / AWS metadata
    "metadata.google", "169.254.169.254",  # cloud metadata endpoints
)

# HTTP method sinks that can exfiltrate data (POST/PUT carry a body)
EXFIL_SINKS = {"requests.post", "requests.put", "requests.patch", "httpx.post", "httpx.put"}


def scan_network_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert network_request CodeFeatures into RiskFindings."""
    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "network_request":
            continue

        snippet = feature.source.snippet
        has_user_inputs = bool(feature.user_controlled_inputs)
        inputs = ", ".join(feature.user_controlled_inputs) if has_user_inputs else "unknown"
        sink = feature.sink
        targets_internal = any(m in snippet for m in INTERNAL_MARKERS)
        is_exfil_sink = sink in EXFIL_SINKS

        # --- Case 1: SSRF — user-controlled URL ---
        if has_user_inputs:
            if targets_internal:
                severity = "critical"
                confidence = 0.90
                attack_path = (
                    f"MCP tool argument(s) {inputs} -> {sink}(url) -> "
                    "request to internal/metadata network endpoint -> SSRF"
                )
                impact = (
                    "Attacker can reach cloud metadata services (e.g., AWS IMDSv1, GCP metadata), "
                    "internal APIs, or services behind the firewall from the MCP server's network context."
                )
                remediation = (
                    "Use a strict URL allowlist. Block requests to RFC-1918 ranges, "
                    "loopback, and cloud metadata endpoints. "
                    "Consider using a dedicated egress proxy that enforces these rules."
                )
                fp_notes = "Internal marker found in snippet; confirm it's in the URL argument, not a comment or log string."
            elif is_exfil_sink:
                severity = "high"
                confidence = 0.80
                attack_path = (
                    f"MCP tool argument(s) {inputs} -> {sink}(url, data=...) -> "
                    "POST/PUT to attacker-controlled endpoint -> data exfiltration"
                )
                impact = (
                    "Attacker can redirect outbound POST/PUT requests to an attacker-controlled server, "
                    "potentially exfiltrating request bodies, tokens, or other sensitive data."
                )
                remediation = (
                    "Validate and allowlist the destination URL before making the request. "
                    "Never allow raw user input as the URL in data-submitting HTTP methods."
                )
                fp_notes = "Fires when user-controlled input is detected in the enclosing MCP tool and the sink is a write-method. Verify the input actually reaches the URL argument."
            else:
                severity = "high"
                confidence = 0.75
                attack_path = (
                    f"MCP tool argument(s) {inputs} -> {sink}(url) -> "
                    "GET request to attacker-controlled or unvalidated URL -> SSRF"
                )
                impact = (
                    "Attacker can cause the MCP server to make GET requests to arbitrary URLs, "
                    "potentially leaking the server's IP, triggering internal side effects, "
                    "or reaching restricted network endpoints."
                )
                remediation = (
                    "Validate the URL against a strict allowlist of permitted domains/schemes. "
                    "Reject private IP ranges, loopback addresses, and file:// / gopher:// schemes."
                )
                fp_notes = "Confidence based on parameter name in enclosing MCP tool. Confirm the parameter actually flows to the URL argument."

        # --- Case 2: Hardcoded URL but targets internal network ---
        elif targets_internal:
            severity = "medium"
            confidence = 0.65
            attack_path = (
                f"Hardcoded internal URL -> {sink} -> "
                "request to internal/metadata endpoint from MCP server"
            )
            impact = (
                "The MCP server makes requests to internal infrastructure or cloud metadata endpoints. "
                "If combined with other vulnerabilities, this could be leveraged for lateral movement."
            )
            remediation = (
                "Audit why the MCP server contacts internal endpoints. "
                "Ensure internal service calls are intentional and scoped to least privilege. "
                "Consider whether this network access should be exposed via an MCP tool at all."
            )
            fp_notes = "No user-controlled input detected; risk depends on whether the URL can be influenced indirectly."

        # --- Case 3: Network call with no obvious risk factors ---
        else:
            severity = "low"
            confidence = 0.50
            attack_path = (
                f"Hardcoded URL -> {sink} -> outbound network request "
                "(low risk unless URL or params can be influenced by tool arguments)"
            )
            impact = "Outbound network call with no detected user-controlled parameters; risk is low."
            remediation = "Confirm the URL is fully hardcoded and not derivable from user or model input."
            fp_notes = "Low-confidence finding; likely benign unless data flow analysis reveals indirect user control."

        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="network_ssrf",
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
