"""
risk_lifecycle.py — Lifecycle risk agent (V1: rule-based, no LLM)

Detects risks that arise from how an MCP server manages state and resources
over the lifetime of a session, rather than from dangerous operations in a
single tool call.

Three risk classes:

    INCOMPLETE_CLEANUP   — file opened without a context manager (bare open()
                           without try/finally), so temp data may persist on disk
                           after a tool call completes.

    LOG_LEAKAGE          — a user-controlled MCP tool parameter name appears on
                           the same line as a logging/print call, suggesting
                           sensitive input may be written to logs.

    SESSION_STATE_LEAK   — a module-level mutable variable (list / dict) is
                           written inside an MCP tool function, creating shared
                           state that is not session-isolated and could leak
                           data between callers.

Confidence scores are intentionally conservative (0.55–0.70) because V1 uses
snippet-level pattern matching rather than full data-flow analysis; false
positives are more likely here than in other agents.

TODO (V2): replace pattern matching with proper taint-tracking and cross-call
           data-flow analysis for more precise session isolation checks.
"""

from __future__ import annotations

import re
import uuid

from mcp_security_agent.schemas import CodeFeature, RiskFinding


# ── Pattern constants ────────────────────────────────────────────────────────

# Matches any open() call; safe usage ('with open(') is filtered in logic below
_OPEN_RE = re.compile(r'\bopen\s*\(')

# Matches logging calls and print statements
_LOG_CALL_RE = re.compile(r'\b(logging\.|logger\.|log\.|print\s*\()')

# Matches assignment to a module-level mutable: name = [] or name = {}
# Used to identify global state containers
_GLOBAL_MUTABLE_RE = re.compile(r'^([A-Za-z_]\w*)\s*=\s*(\[\]|\{\})', re.MULTILINE)


# ── Public entry point ───────────────────────────────────────────────────────

def scan_lifecycle_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert CodeFeature objects into lifecycle RiskFindings."""
    findings: list[RiskFinding] = []
    findings += _check_incomplete_cleanup(features)
    findings += _check_log_leakage(features)
    findings += _check_session_state(features)
    return findings


# ── Risk checks ──────────────────────────────────────────────────────────────

def _check_incomplete_cleanup(features: list[CodeFeature]) -> list[RiskFinding]:
    """
    Flag file_access features where open() is called without a context manager.

    A bare `f = open(path)` without a `with` block or explicit `try/finally`
    means the file handle (and any temp data) may not be closed or deleted
    if an exception occurs mid-tool-call.
    """
    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "file_access":
            continue

        snippet = feature.source.snippet

        # Safe pattern: 'with open(...)' — skip
        if "with open(" in snippet or "with open (" in snippet:
            continue

        # Unsafe pattern: bare open() call (not caught by the with-block check above)
        if not _OPEN_RE.search(snippet):
            continue

        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="lifecycle_leak",
            severity="medium",
            confidence=0.65,
            file_path=feature.source.file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=(
                "MCP tool opens file without context manager → exception mid-call "
                "→ file handle not closed → temp data persists on disk"
            ),
            impact=(
                "Temporary files containing sensitive data (user input, intermediate "
                "results) may not be deleted after the tool call, leaving them "
                "accessible to other processes or future requests."
            ),
            remediation=(
                "Use `with open(...) as f:` to guarantee the file is closed on exit. "
                "For temp files, use `tempfile.NamedTemporaryFile(delete=True)` or "
                "`tempfile.TemporaryDirectory()` as a context manager."
            ),
            false_positive_notes=(
                "May fire on read-only opens where persistence is harmless. "
                "Confirm whether the opened file contains sensitive data."
            ),
            source_feature_id=feature.feature_id,
        ))

    return findings


def _check_log_leakage(features: list[CodeFeature]) -> list[RiskFinding]:
    """
    Flag MCP tool features where a user-controlled parameter name appears
    on the same line as a logging or print call.

    This is a strong signal that the raw tool argument is being written to
    logs, which may expose user data, file contents, or injected payloads.
    """
    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "mcp_tool":
            continue
        if not feature.user_controlled_inputs:
            continue

        snippet = feature.source.snippet
        leaking_params: list[str] = []

        for line in snippet.splitlines():
            if not _LOG_CALL_RE.search(line):
                continue
            for param in feature.user_controlled_inputs:
                if param in line:
                    leaking_params.append(param)

        if not leaking_params:
            continue

        leaked = ", ".join(sorted(set(leaking_params)))
        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="lifecycle_leak",
            severity="medium",
            confidence=0.60,
            file_path=feature.source.file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=(
                f"MCP tool parameter(s) [{leaked}] → interpolated into "
                "logging/print call → written to log file → potential data exposure"
            ),
            impact=(
                "Sensitive user input (file paths, query strings, prompt content) "
                "logged in plaintext. Log files may be readable by other users, "
                "shipped to external systems, or retained beyond the session lifetime."
            ),
            remediation=(
                "Never log raw tool parameters. Redact or truncate sensitive fields "
                "before logging. Consider structured logging with explicit field "
                "allowlists rather than f-string interpolation."
            ),
            false_positive_notes=(
                "Match is based on parameter name appearing in the same line as a "
                "log call — the parameter may be a different local variable with the "
                "same name. Verify the data flow manually."
            ),
            source_feature_id=feature.feature_id,
        ))

    return findings


def _check_session_state(features: list[CodeFeature]) -> list[RiskFinding]:
    """
    Flag MCP tool features whose snippets write into a module-level mutable
    (list or dict), which is a common pattern for unintentional shared state.

    If two concurrent or sequential callers share the same server process,
    data written by one caller may be visible to another.
    """
    findings: list[RiskFinding] = []

    # Collect module-level mutable variable names from all mcp_tool snippets.
    # These are names that appear to be initialised at module scope as [] or {}.
    global_names: set[str] = set()
    for feature in features:
        if feature.feature_type == "mcp_tool":
            for match in _GLOBAL_MUTABLE_RE.finditer(feature.source.snippet):
                global_names.add(match.group(1))

    if not global_names:
        return findings

    # Now look for assignments or appends to those names inside tool snippets
    _write_re = re.compile(
        r'\b(' + '|'.join(re.escape(n) for n in global_names) + r')\b'
        r'\s*(\[.*?\]\s*=|\.append\(|\.update\(|\.extend\(|\s*=\s*)'
    )

    for feature in features:
        if feature.feature_type != "mcp_tool":
            continue

        snippet = feature.source.snippet
        matches = _write_re.findall(snippet)
        if not matches:
            continue

        written = ", ".join(sorted({m[0] for m in matches}))
        findings.append(RiskFinding(
            finding_id=str(uuid.uuid4())[:8],
            risk_type="lifecycle_leak",
            severity="low",
            confidence=0.55,
            file_path=feature.source.file_path,
            line_range=(feature.source.line_start, feature.source.line_end),
            evidence=snippet,
            attack_path=(
                f"MCP tool writes to module-level variable(s) [{written}] → "
                "state persists across tool calls → data from one session "
                "visible to subsequent callers sharing the same process"
            ),
            impact=(
                "Shared mutable state across tool calls can cause data leakage "
                "between sessions if the MCP server handles multiple callers "
                "in a single process without per-session isolation."
            ),
            remediation=(
                "Avoid module-level mutable state in MCP servers. Pass state "
                "through function arguments or use session-scoped objects. "
                "If shared state is required, protect it with appropriate "
                "locking and explicit per-session namespacing."
            ),
            false_positive_notes=(
                "Confidence is low — V1 matches by variable name only. "
                "The write may be inside a lock or the server may be single-threaded. "
                "Verify whether the server handles concurrent or sequential sessions."
            ),
            source_feature_id=feature.feature_id,
        ))

    return findings
