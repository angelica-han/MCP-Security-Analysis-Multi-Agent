"""
functional.py — Capability Analysis Agent (V1: rule-based, no LLM)

Infers what an MCP project does from FileInventory + CodeFeature objects
produced by the AST scanner. No LLM in V1: sensitive capabilities map
directly from code feature types to capability names.

Runs AFTER node_extract in the graph so code_features are already available.

TODO (V2): wrap with an LLM layer for richer trust_boundary descriptions
and capability inference for JS/TS projects where AST coverage is limited.
"""

from __future__ import annotations

from collections import defaultdict

from mcp_security_agent.schemas import CodeFeature, FileInventory, ProjectProfile


# ── Filename heuristics ──────────────────────────────────────────────────────

_SERVER_ENTRY_NAMES = {
    "server.py", "mcp_server.py", "main.py", "app.py",
    "index.py", "index.ts", "index.js",
}
_CLIENT_ENTRY_NAMES = {
    "client.py", "mcp_client.py", "client.ts", "client.js",
}

# ── feature_type → sensitive capability label ────────────────────────────────

_FEATURE_TO_CAPABILITY: dict[str, str] = {
    "command_execution":   "shell_exec",
    "file_access":         "file_read",
    "network_request":     "network",
    "prompt_construction": "prompt_construction",
}


def analyze_capabilities(
    file_inventory: FileInventory,
    code_features: list[CodeFeature],
) -> ProjectProfile:
    """
    Derive a ProjectProfile from FileInventory + CodeFeature list.

    Every field traces back to a concrete file name or CodeFeature object, no LLM required in V1.
    """

    # ── 1. project_type ─────────────────────────────────────────────────────
    file_base_names = {
        fi.path.split("/")[-1].lower()
        for fi in file_inventory.candidate_files
    }

    has_server_entry = bool(file_base_names & _SERVER_ENTRY_NAMES)
    has_client_entry = bool(file_base_names & _CLIENT_ENTRY_NAMES)
    has_mcp_tool     = any(f.feature_type == "mcp_tool" for f in code_features)

    if has_mcp_tool or has_server_entry:
        project_type: str = "mixed" if has_client_entry else "mcp_server"
    elif has_client_entry:
        project_type = "mcp_client"
    else:
        project_type = "unknown"

    # ── 2. entry_points ─────────────────────────────────────────────────────
    # Files flagged as entry points by the inventory scanner, plus any file
    # that registers MCP tools (always high-value for security scanning).
    entry_set: set[str] = {
        fi.path for fi in file_inventory.candidate_files if fi.is_entry
    }
    tool_files: set[str] = {
        f.source.file_path for f in code_features if f.feature_type == "mcp_tool"
    }
    entry_points = sorted(entry_set | tool_files)

    # ── 3. mcp_capabilities ─────────────────────────────────────────────────
    mcp_capabilities: list[str] = []
    if has_mcp_tool:
        mcp_capabilities.append("tools")
    # V2: detect "resources" and "prompts" registrations

    # ── 4. sensitive_capabilities ───────────────────────────────────────────
    seen_caps: set[str] = set()
    sensitive_capabilities: list[str] = []
    for feature in code_features:
        cap = _FEATURE_TO_CAPABILITY.get(feature.feature_type)
        if cap and cap not in seen_caps:
            seen_caps.add(cap)
            sensitive_capabilities.append(cap)

    # ── 5. trust_boundary ───────────────────────────────────────────────────
    trust_boundary = _build_trust_boundary(code_features, sensitive_capabilities)

    # ── 6. files_for_deep_scan ──────────────────────────────────────────────
    # Priority 1: files that register MCP tools AND contain dangerous sinks
    #   → these are where injection-to-execution paths are most likely.
    # Priority 2: entry-point files not already listed.
    sink_types_by_file: dict[str, set[str]] = defaultdict(set)
    for f in code_features:
        if f.feature_type != "mcp_tool":
            sink_types_by_file[f.source.file_path].add(f.feature_type)

    files_for_deep_scan: list[dict] = []
    seen_deep: set[str] = set()

    for path in sorted(tool_files):
        sinks = sink_types_by_file.get(path, set())
        reason = (
            f"registers MCP tools and contains: {', '.join(sorted(sinks))}"
            if sinks
            else "registers MCP tools (entry point for user-controlled input)"
        )
        files_for_deep_scan.append({"path": path, "reason": reason})
        seen_deep.add(path)

    for ep in entry_points:
        if ep not in seen_deep:
            files_for_deep_scan.append({"path": ep, "reason": "entry-point file"})

    # ── 7. summary ──────────────────────────────────────────────────────────
    summary = _build_summary(
        project_type=project_type,
        file_inventory=file_inventory,
        mcp_capabilities=mcp_capabilities,
        sensitive_capabilities=sensitive_capabilities,
    )

    return ProjectProfile(
        project_type=project_type,
        entry_points=entry_points,
        mcp_capabilities=mcp_capabilities,
        sensitive_capabilities=sensitive_capabilities,
        trust_boundary=trust_boundary,
        files_for_deep_scan=files_for_deep_scan,
        summary=summary,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_trust_boundary(
    code_features: list[CodeFeature],
    sensitive_capabilities: list[str],
) -> str:
    """
    Describe the trust boundary: which user-controlled MCP tool parameters
    can reach which dangerous sinks.
    """
    if not code_features:
        return "No code features extracted; trust boundary unknown."

    # tool name → set of user-controlled params
    tool_params: dict[str, set[str]] = defaultdict(set)
    for f in code_features:
        if f.feature_type == "mcp_tool" and f.user_controlled_inputs:
            tool_params[f.sink].update(f.user_controlled_inputs)

    # all dangerous sinks found outside of tool registrations
    sink_names: set[str] = {
        f.sink
        for f in code_features
        if f.feature_type != "mcp_tool" and f.sink
    }

    if not tool_params and not sensitive_capabilities:
        return "No MCP tool registrations or dangerous sinks detected."

    parts: list[str] = []

    if tool_params:
        summaries = [
            f"'{tool}' exposes [{', '.join(sorted(params))}]"
            for tool, params in list(tool_params.items())[:3]
        ]
        parts.append(
            "User-controlled inputs enter via MCP tool parameters: "
            + "; ".join(summaries) + "."
        )

    if sink_names:
        parts.append(f"These inputs can reach: {', '.join(sorted(sink_names))}.")

    if sensitive_capabilities:
        parts.append(
            f"Sensitive capability surface: {', '.join(sensitive_capabilities)}."
        )

    return " ".join(parts) if parts else "Trust boundary indeterminate from available features."


def _build_summary(
    project_type: str,
    file_inventory: FileInventory,
    mcp_capabilities: list[str],
    sensitive_capabilities: list[str],
) -> str:
    """One-paragraph natural-language summary of the project."""
    lang_parts = ", ".join(
        f"{count} {lang}"
        for lang, count in sorted(
            file_inventory.language_distribution.items(), key=lambda x: -x[1]
        )
    ) or "unknown language"

    type_label = {
        "mcp_server": "MCP Server",
        "mcp_client": "MCP Client",
        "mixed":      "MCP Server + Client",
        "unknown":    "MCP project (type unclear)",
    }[project_type]

    cap_str  = ", ".join(mcp_capabilities)      if mcp_capabilities      else "none detected"
    sens_str = ", ".join(sensitive_capabilities) if sensitive_capabilities else "none detected"

    return (
        f"This appears to be a {type_label} ({lang_parts}). "
        f"MCP capabilities: {cap_str}. "
        f"Sensitive capabilities detected: {sens_str}. "
        f"Total candidate files: {file_inventory.total_files}."
    )
