"""
Prompt injection risk agent — LLM-backed.

If get_llm() returns None (no
   key configured) or any call/parse fails, we fall back to the ORIGINAL
   deterministic judgment, so the agent still runs with zero credentials and
   its output shape never changes.
"""

from __future__ import annotations

import json
import re
import uuid

from mcp_security_agent.llm import get_llm
from mcp_security_agent.schemas import CodeFeature, RiskFinding


def scan_prompt_injection_risks(features: list[CodeFeature]) -> list[RiskFinding]:
    """Convert prompt_construction + mcp_tool CodeFeatures into RiskFindings."""

    # Index mcp_tool features by file. The snippet is the full function body,
    tools_by_file: dict[str, list[CodeFeature]] = {}
    for f in features:
        if f.feature_type == "mcp_tool":
            tools_by_file.setdefault(f.source.file_path, []).append(f)

    # Built once. None when no key is configured → every feature uses the
    # deterministic fallback.
    llm = get_llm()

    findings: list[RiskFinding] = []

    for feature in features:
        if feature.feature_type != "prompt_construction":
            continue

        file_tools = tools_by_file.get(feature.source.file_path, [])
        enclosing = _enclosing_tool(feature, file_tools)

        judgment: dict | None = None
        if llm is not None:
            result = _llm_judge(llm, feature, enclosing, file_tools)
            if result == "safe":
                continue
            if isinstance(result, dict):
                judgment = result
            # result is None → LLM call/parse failed → fall through to regex.

        if judgment is None:
            judgment = _deterministic_judge(feature, file_tools)

        findings.append(_build_finding(feature, judgment))

    return findings


# ──────────────────────────────────────────────────────────────────────────
# LLM judgment (primary path)
# ──────────────────────────────────────────────────────────────────────────

def _llm_judge(
    llm,
    feature: CodeFeature,
    enclosing: CodeFeature | None,
    file_tools: list[CodeFeature],
) -> dict | str | None:
    """
    Ask the LLM whether untrusted tool input really reaches this prompt.

    Returns:
        dict   — a real injection; fields drive the RiskFinding.
        "safe" — LLM judged it a non-issue (false positive cleared); skip it.
        None   — LLM unavailable / call failed / unparseable; caller falls back
                 to the deterministic judgment.
    """
    prompt_snippet = feature.source.snippet

    if enclosing is not None:
        tool_src = enclosing.source.snippet          # full function body
        params = enclosing.user_controlled_inputs
        tool_name = enclosing.sink                   # mcp_tool stores name in sink
    else:
        # No tool wraps this prompt — judge on the prompt line alone, with any
        # user-controlled params known in the file.
        tool_src = prompt_snippet
        params = sorted({p for t in file_tools for p in t.user_controlled_inputs})
        tool_name = ""

    system = (
        "You are a security code reviewer for MCP (Model Context Protocol) "
        "servers. You are given the full source of one MCP tool and ONE "
        "prompt-like string built inside it. Decide whether UNTRUSTED tool "
        "input (the listed user-controlled parameters) actually reaches that "
        "string and is interpreted as LLM INSTRUCTIONS, creating a prompt-"
        "injection risk.\n"
        "Be strict to avoid false positives. Answer is_injection=false when:\n"
        "- the parameter is validated against a fixed allowlist before use,\n"
        "- the parameter is reassigned to a constant before the string is "
        "built,\n"
        "- the string is a user-facing message or log line that is never sent "
        "to an LLM as instructions.\n"
        "Answer is_injection=true only when attacker-controlled text can change "
        "the instructions an LLM receives. severity: high = untrusted text "
        "flows directly into LLM instructions; medium = dynamic prompt with "
        "plausibly-untrusted input but no confirmed flow; low = weak/indirect.\n"
        'Respond with ONLY a JSON object: '
        '{"is_injection": <bool>, "tainted_params": [<param names>], '
        '"severity": "high"|"medium"|"low", "confidence": <float 0.0-1.0>, '
        '"reason": "<one sentence>"}.'
    )
    human = (
        f"MCP tool name: {tool_name or '(unknown)'}\n"
        f"User-controlled tool parameters: {params or '(none detected)'}\n\n"
        f"Full tool source:\n{tool_src}\n\n"
        f"Prompt-like string under review:\n{prompt_snippet}"
    )

    try:
        resp = llm.invoke([("system", system), ("human", human)])
        text = (getattr(resp, "content", "") or "").strip()
    except Exception:
        return None  # network / key / quota / timeout → fall back to regex

    data = _parse_json(text)
    if data is None:
        return None

    if not bool(data.get("is_injection")):
        return "safe"

    severity = data.get("severity")
    if severity not in ("high", "medium", "low"):
        severity = "medium"

    try:
        conf = float(data.get("confidence"))
    except (TypeError, ValueError):
        conf = 0.6
    conf = max(0.0, min(1.0, conf))

    tainted = data.get("tainted_params")
    tainted = [str(p) for p in tainted] if isinstance(tainted, list) else []

    reason = str(data.get("reason", "")).strip()

    return {
        "severity": severity,
        "confidence": conf,
        "controlled_params": tainted,
        "tool_name": tool_name,
        "notes": f"LLM judgment: {reason}" if reason else "LLM-judged prompt injection.",
    }


# ──────────────────────────────────────────────────────────────────────────
# Deterministic judgment (fallback — the ORIGINAL logic, unchanged)
# ──────────────────────────────────────────────────────────────────────────

def _deterministic_judge(feature: CodeFeature, file_tools: list[CodeFeature]) -> dict:
    """
    Original regex-based judgment, used whenever the LLM is unavailable or fails.
    A tool param name appearing verbatim in the snippet → high; otherwise medium.
    """
    snippet = feature.source.snippet

    controlled_params: list[str] = []
    tool_name = ""
    for t in file_tools:
        for param in t.user_controlled_inputs:
            if _param_in_snippet(param, snippet):
                controlled_params.append(param)
                tool_name = t.sink

    if controlled_params:
        return {
            "severity": "high",
            "confidence": 0.85,
            "controlled_params": controlled_params,
            "tool_name": tool_name,
            "notes": (
                "Rule fires when a tool param name appears verbatim in the f-string "
                "snippet. May miss renamed variables or multi-step flows; may "
                "false-positive on same-named variables that are not actually the "
                "tool param."
            ),
        }
    return {
        "severity": "medium",
        "confidence": 0.60,
        "controlled_params": [],
        "tool_name": "",
        "notes": (
            "No direct MCP tool parameter taint detected. Risk is conditional on "
            "whether interpolated values are user-controlled."
        ),
    }


# ──────────────────────────────────────────────────────────────────────────
# Shared finding builder + helpers
# ──────────────────────────────────────────────────────────────────────────

def _build_finding(feature: CodeFeature, j: dict) -> RiskFinding:
    """Assemble a RiskFinding. Output shape is identical to the original agent."""
    controlled = j["controlled_params"]
    tool_name = j.get("tool_name", "")

    if controlled:
        attack_path = (
            f"MCP tool '{tool_name}' parameter(s) {controlled} "
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
    else:
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

    return RiskFinding(
        finding_id=str(uuid.uuid4())[:8],
        risk_type="prompt_injection",
        severity=j["severity"],
        confidence=j["confidence"],
        file_path=feature.source.file_path,
        line_range=(feature.source.line_start, feature.source.line_end),
        evidence=feature.source.snippet,
        attack_path=attack_path,
        impact=impact,
        remediation=remediation,
        false_positive_notes=j.get("notes", ""),
        source_feature_id=feature.feature_id,
    )


def _enclosing_tool(
    feature: CodeFeature, file_tools: list[CodeFeature]
) -> CodeFeature | None:
    """
    Find the mcp_tool whose line range contains this prompt feature (the function
    the prompt is built inside). Falls back to the first tool in the file, then None.
    """
    fs = feature.source.line_start
    for t in file_tools:
        if t.source.line_start <= fs <= t.source.line_end:
            return t
    return file_tools[0] if file_tools else None


def _parse_json(text: str) -> dict | None:
    """
    Extract the first {...} JSON object from the model's reply, tolerant of code
    fences or surrounding prose. Returns None if nothing parseable is found.
    """
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _param_in_snippet(param: str, snippet: str) -> bool:
    """
    Check if a parameter name appears in a code snippet as a standalone identifier.
    Covers {param}, f'{param}', and plain variable references.
    """
    pattern = r'(?<![a-zA-Z0-9_])' + re.escape(param) + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, snippet))
