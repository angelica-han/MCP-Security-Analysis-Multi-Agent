"""
llm_evaluator.py — LLM second-opinion for low-confidence findings.

The rule-based Evaluator reduces FALSE NEGATIVES (drops empty/low-confidence
findings, merges duplicates). This module adds a check on the TRUE-POSITIVE
side: for findings the agents were unsure about, an LLM re-reads the actual
source code and issues its OWN confidence — completely BLIND to the agent's
score and reasoning, so the two judgments are independent.

Why blind matters: the agents score with hard-coded condition combinations, so
a low score does not technically mean "no risk". An independent read can both
rescue under-scored real risks and demote over-scored false positives. And
because the LLM never sees the agent's verdict, it cannot anchor to it — the
divergence between agent and LLM is a clean signal of which agents are weak.

Grounding discipline (same as the reporter): the LLM only emits a judgment
(confidence + one-line reason). It never rewrites evidence. Findings without
evidence are dropped by the rule layer BEFORE they ever reach this module.
"""

from __future__ import annotations

import json

from mcp_security_agent.llm import get_llm


# Plain-language definition of each risk category, so the LLM knows what to look
# for. This is general security knowledge — NOT the agent's reasoning or verdict.
_RISK_DEFINITIONS = {
    "prompt_injection": (
        "Untrusted/user-controlled input is interpolated into a prompt or tool "
        "description, letting an attacker override instructions sent to an LLM."
    ),
    "command_exec": (
        "User-controlled input reaches an OS command sink (e.g. subprocess with "
        "shell=True, os.system), allowing arbitrary command execution."
    ),
    "file_access": (
        "User-controlled input reaches a filesystem path without validation, "
        "allowing path traversal or reads/writes of arbitrary files."
    ),
    "network_ssrf": (
        "User-controlled input reaches an outbound request URL without validation, "
        "allowing server-side request forgery to internal or arbitrary endpoints."
    ),
    "lifecycle_leak": (
        "Session state, secrets, or resources leak across the lifetime of a "
        "session due to incomplete cleanup or logging of sensitive data."
    ),
}


class LLMEvaluator:
    """
    Wraps the shared LLM and re-judges a single finding's code, blind.

    Usage:
        ev = LLMEvaluator()
        if ev.available:
            result = ev.rejudge("command_exec", code_context)
            # result is (confidence, rationale) or None on failure
    """

    def __init__(self) -> None:
        self._llm = get_llm()

    @property
    def available(self) -> bool:
        """True if an LLM is configured. If False, callers keep the agent score."""
        return self._llm is not None

    def rejudge(self, risk_type: str, code_context: str) -> tuple[float, str] | None:
        """
        Independently judge whether `code_context` contains a real, exploitable
        instance of `risk_type`. Returns (confidence, one_line_reason), or None
        if the LLM is unavailable or the call/parse fails (caller keeps agent score).

        The prompt deliberately contains NO information about the agent's score,
        attack path, or accept/reject decision — the judgment must be independent.
        """
        if self._llm is None:
            return None

        definition = _RISK_DEFINITIONS.get(risk_type, risk_type)
        system = (
            "You are a security code reviewer for MCP (Model Context Protocol) "
            "servers and clients. You are given a code snippet and ONE risk "
            "category to assess. Decide INDEPENDENTLY whether this code contains a "
            "real, exploitable instance of that risk, based ONLY on the code shown. "
            "Be calibrated: a confidence near 1.0 means clearly exploitable, near "
            "0.0 means clearly not a real instance of this risk. "
            'Respond with ONLY a JSON object: '
            '{"confidence": <float 0.0-1.0>, "reason": "<one sentence>"}.'
        )
        human = (
            f"Risk category to assess: {risk_type}\n"
            f"Definition: {definition}\n\n"
            f"Code:\n{code_context}"
        )

        try:
            resp = self._llm.invoke([("system", system), ("human", human)])
            text = (getattr(resp, "content", "") or "").strip()
            conf, reason = _parse_judgment(text)
            if conf is None:
                return None
            return conf, reason
        except Exception:
            # Network error, bad key, quota, timeout — caller keeps the agent score.
            return None


def _parse_judgment(text: str) -> tuple[float | None, str]:
    """
    Extract (confidence, reason) from the model's reply. Tolerant of code fences
    or extra prose around the JSON. Returns (None, "") if it can't be parsed,
    so the caller can fall back to the agent's score.
    """
    if not text:
        return None, ""

    # Grab the first {...} block, even if wrapped in ```json fences or prose.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None, ""

    try:
        data = json.loads(text[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None, ""

    conf = data.get("confidence")
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        return None, ""
    conf = max(0.0, min(1.0, conf))  # clamp into [0, 1]

    reason = str(data.get("reason", "")).strip()
    return conf, reason
