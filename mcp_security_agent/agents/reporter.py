"""
reporter.py — Report Generation Agent

Assembles the final security report from accepted RiskFindings, ProjectProfile,
and EvalResult. Every claim in the report traces back to a finding field —
no new risks, file paths, or line numbers are invented here.

Sections produced:
    1. Executive Summary   — overall risk level + main surfaces + recommendation
    2. Risk Findings       — per-finding detail: evidence, attack path, impact, fix
    3. Action Plan         — P0 / P1 / P2 prioritised remediation tasks
    4. Coverage Notes      — what was scanned, skipped, confidence caveats

LLM layer (current): the Executive Summary is polished by an LLM that is given
ONLY the pre-computed facts (counts, severities, risk surfaces) — it rephrases,
it does not analyse code or invent findings. If no API key is configured or the
call fails, a deterministic summary is used instead, so the pipeline always runs.

TODO (next): extend the LLM layer to the action plan / per-finding narrative.
"""

from __future__ import annotations

import json
from datetime import datetime

from mcp_security_agent.llm import get_llm
from mcp_security_agent.schemas import (
    EvalResult,
    FinalReport,
    ProjectProfile,
    RagContext,
    RiskFinding,
    ScanRequest,
)

# Severity order — highest index = most severe
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Emoji badges for severity levels in the markdown
_SEVERITY_BADGE = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
}

# Action plan priority mapping
_SEVERITY_TO_PRIORITY = {
    "critical": "P0",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P2",
}


def generate_report(
    findings: list[RiskFinding],
    project_profile: ProjectProfile | None,
    eval_result: EvalResult | None,
    scan_request: ScanRequest,
    use_llm: bool = True,
    rag_contexts: list[RagContext] | None = None,
) -> FinalReport:
    """
    Build a FinalReport from accepted findings and pipeline metadata.

    Parameters
    ----------
    findings:
        The accepted RiskFindings (already filtered by the Evaluator node).
    project_profile:
        Capability analysis output; used for coverage notes and summary context.
    eval_result:
        Evaluator output; used for confidence score and coverage gap notes.
    scan_request:
        Original scan request; used for project path and config metadata.
    use_llm:
        If True (default), polish the executive summary with an LLM. Set False
        to force the deterministic summary (useful for tests / reproducibility).
    rag_contexts:
        Knowledge-base references retrieved for accepted findings (RAG node).
        Rendered as a per-finding "References" section — titles and source URLs
        only, verbatim from the knowledge base. None / empty list = no section.
    """

    # ── 1. Overall risk level ────────────────────────────────────────────────
    overall_risk_level = _compute_risk_level(findings)

    # ── 2. Executive summary ─────────────────────────────────────────────────
    # The deterministic summary is always built first: it is both the zero-key
    # output and the fallback if the LLM is unavailable or the call fails.
    executive_summary = _build_executive_summary(
        findings=findings,
        overall_risk_level=overall_risk_level,
        project_profile=project_profile,
    )
    if use_llm:
        executive_summary = _llm_executive_summary(
            findings=findings,
            overall_risk_level=overall_risk_level,
            project_profile=project_profile,
            fallback=executive_summary,
        )

    # ── 3. Action plan (P0 / P1 / P2) ───────────────────────────────────────
    action_plan = _build_action_plan(findings)

    # ── 4. Coverage notes ────────────────────────────────────────────────────
    coverage_notes = _build_coverage_notes(
        scan_request=scan_request,
        project_profile=project_profile,
        eval_result=eval_result,
    )

    # ── 5. Full Markdown report ──────────────────────────────────────────────
    report_markdown = _render_markdown(
        scan_request=scan_request,
        overall_risk_level=overall_risk_level,
        executive_summary=executive_summary,
        findings=findings,
        action_plan=action_plan,
        coverage_notes=coverage_notes,
        eval_result=eval_result,
        rag_by_finding={c.finding_id: c for c in (rag_contexts or [])},
    )

    return FinalReport(
        project_path=scan_request.project_path,
        overall_risk_level=overall_risk_level,
        executive_summary=executive_summary,
        accepted_findings=findings,
        coverage_notes=coverage_notes,
        action_plan=action_plan,
        report_markdown=report_markdown,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _llm_executive_summary(
    findings: list[RiskFinding],
    overall_risk_level: str,
    project_profile: ProjectProfile | None,
    fallback: str,
) -> str:
    """
    Polish the executive summary with an LLM, grounded strictly in pre-computed facts.

    The LLM is handed ONLY a small JSON of facts (counts, severities, risk
    surfaces, capabilities) — it never sees raw source code, so it cannot invent
    findings, file names, or numbers. If the LLM is unavailable (no key / missing
    package) or the call fails for any reason, the deterministic `fallback` is
    returned, so the pipeline never breaks.
    """
    llm = get_llm()
    if llm is None:
        return fallback

    # Same facts the deterministic builder relies on — nothing more.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    facts = {
        "overall_risk_level": overall_risk_level,
        "total_findings": len(findings),
        "finding_counts_by_severity": counts,
        "risk_surfaces": sorted({f.risk_type for f in findings}),
        "project_type": project_profile.project_type if project_profile else None,
        "sensitive_capabilities": (
            project_profile.sensitive_capabilities if project_profile else []
        ),
    }

    system = (
        "You write the executive summary for an automated MCP security scan report. "
        "Write 2-4 sentences of plain prose: no markdown, no headings, no bullet lists. "
        "Use ONLY the facts in the JSON provided. Do NOT invent findings, file names, "
        "numbers, or risks that are absent from the data. Keep the tone consistent with "
        "overall_risk_level — never downplay a critical or high result."
    )
    human = (
        "Facts (JSON):\n"
        f"{json.dumps(facts, indent=2)}\n\n"
        "Write the executive summary now."
    )

    try:
        resp = llm.invoke([("system", system), ("human", human)])
        text = (getattr(resp, "content", "") or "").strip()
        # Guard against an empty or runaway response; fall back if either.
        if not text or len(text) > 1500:
            return fallback
        return text
    except Exception:
        # Network error, bad key, quota exceeded — fall back to deterministic prose.
        return fallback


def _compute_risk_level(findings: list[RiskFinding]) -> str:
    if not findings:
        return "safe"
    worst = max(findings, key=lambda f: _SEVERITY_ORDER[f.severity])
    return worst.severity


def _build_executive_summary(
    findings: list[RiskFinding],
    overall_risk_level: str,
    project_profile: ProjectProfile | None,
) -> str:
    if not findings:
        return (
            "No security findings were identified in this scan. "
            "The project appears safe within the scope of the categories analysed."
        )

    # Count by severity
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    count_parts = ", ".join(
        f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: -_SEVERITY_ORDER[x[0]])
    )

    # Unique risk types
    risk_types = sorted({f.risk_type for f in findings})
    risk_surface = ", ".join(risk_types)

    # Recommendation
    if overall_risk_level == "critical":
        recommendation = "Deployment is NOT recommended until critical findings are resolved."
    elif overall_risk_level == "high":
        recommendation = "Resolve high-severity findings before deploying to production."
    else:
        recommendation = "Review and address findings before wider deployment."

    profile_note = ""
    if project_profile:
        profile_note = (
            f" The project is identified as a {project_profile.project_type} "
            f"with sensitive capabilities: {', '.join(project_profile.sensitive_capabilities)}."
        )

    return (
        f"Scan identified {len(findings)} finding(s) ({count_parts}) "
        f"across the following risk surfaces: {risk_surface}.{profile_note} "
        f"{recommendation}"
    )


def _build_action_plan(findings: list[RiskFinding]) -> list[str]:
    """
    Produce a prioritised remediation task list.
    P0 = critical, P1 = high, P2 = medium/low.
    """
    # Sort: critical first, then high, then medium/low; within same severity sort by file
    sorted_findings = sorted(
        findings,
        key=lambda f: (-_SEVERITY_ORDER[f.severity], f.file_path, f.line_range[0]),
    )

    tasks: list[str] = []
    for f in sorted_findings:
        priority = _SEVERITY_TO_PRIORITY[f.severity]
        loc = f"`{f.file_path}` line {f.line_range[0]}"
        tasks.append(
            f"[{priority}] {f.risk_type} in {loc} — {f.remediation}"
        )
    return tasks


def _build_coverage_notes(
    scan_request: ScanRequest,
    project_profile: ProjectProfile | None,
    eval_result: EvalResult | None,
) -> str:
    parts: list[str] = []

    # What was requested
    requested = scan_request.config.risk_categories
    parts.append(f"Requested scan categories: {', '.join(requested)}.")

    # What was activated (from profile)
    if project_profile:
        caps = project_profile.sensitive_capabilities
        parts.append(
            f"Active capabilities detected: {', '.join(caps) if caps else 'none'}."
        )

    # Evaluator confidence and notes
    if eval_result:
        parts.append(f"Overall finding confidence: {eval_result.overall_confidence:.0%}.")
        if eval_result.missing_categories:
            parts.append(
                f"Categories with no findings (possible gaps): "
                f"{', '.join(eval_result.missing_categories)}."
            )
        if eval_result.evaluator_notes:
            parts.append(f"Evaluator notes: {eval_result.evaluator_notes}")

    # Lifecycle always noted as out of scope in V1
    if "lifecycle" not in requested:
        parts.append(
            "Lifecycle risk (session leakage, incomplete cleanup) was not scanned in this run "
            "— risk_lifecycle agent is planned for V2."
        )

    return " ".join(parts)


def _render_markdown(
    scan_request: ScanRequest,
    overall_risk_level: str,
    executive_summary: str,
    findings: list[RiskFinding],
    action_plan: list[str],
    coverage_notes: str,
    eval_result: EvalResult | None,
    rag_by_finding: dict[str, RagContext] | None = None,
) -> str:
    rag_by_finding = rag_by_finding or {}
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    confidence = f"{eval_result.overall_confidence:.0%}" if eval_result else "N/A"

    # ── Header ───────────────────────────────────────────────────────────────
    lines += [
        "# MCP Security Analysis Report",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Project** | `{scan_request.project_path}` |",
        f"| **Overall Risk** | {_SEVERITY_BADGE.get(overall_risk_level, overall_risk_level.upper())} |",
        f"| **Findings** | {len(findings)} accepted |",
        f"| **Confidence** | {confidence} |",
        f"| **Scan Date** | {now} |",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "---",
        "",
    ]

    # ── Risk Findings ─────────────────────────────────────────────────────────
    lines += ["## Risk Findings", ""]

    if not findings:
        lines += ["*No findings to report.*", ""]
    else:
        # Group by severity for readability
        for severity in ["critical", "high", "medium", "low"]:
            group = [f for f in findings if f.severity == severity]
            if not group:
                continue
            badge = _SEVERITY_BADGE[severity]
            lines += [f"### {badge}", ""]
            for f in group:
                lines += [
                    f"#### `{f.file_path}` — lines {f.line_range[0]}–{f.line_range[1]}",
                    "",
                    f"**Risk type:** `{f.risk_type}`  ",
                    f"**Confidence:** {f.confidence:.0%}",
                    "",
                    "**Evidence:**",
                    "```",
                    f.evidence,
                    "```",
                    "",
                    f"**Attack path:** {f.attack_path}",
                    "",
                    f"**Impact:** {f.impact}",
                    "",
                    f"**Remediation:** {f.remediation}",
                    "",
                ]
                # References retrieved by the RAG node — titles and source URLs
                # verbatim from the knowledge base. Findings whose retrieval
                # returned nothing relevant get no section (never force a citation).
                ctx = rag_by_finding.get(f.finding_id)
                if ctx and ctx.documents:
                    lines += ["**References:**", ""]
                    for doc in ctx.documents:
                        link = f"[{doc.title}]({doc.source})" if doc.source else doc.title
                        lines.append(f"- {link}")
                    lines += [""]
                if f.false_positive_notes:
                    lines += [
                        f"> ⚠️ False-positive note: {f.false_positive_notes}",
                        "",
                    ]
                lines += ["---", ""]

    # ── Action Plan ───────────────────────────────────────────────────────────
    lines += ["## Action Plan", ""]

    for priority in ["P0", "P1", "P2"]:
        tasks = [t for t in action_plan if t.startswith(f"[{priority}]")]
        if not tasks:
            continue
        label = {"P0": "Fix Immediately (Critical)", "P1": "Fix Soon (High)", "P2": "Fix When Possible (Medium / Low)"}[priority]
        lines += [f"### {priority} — {label}", ""]
        for task in tasks:
            # Strip the [Px] prefix for display under the header
            lines.append(f"- [ ] {task[5:].strip()}")
        lines.append("")

    lines += ["---", ""]

    # ── Coverage Notes ────────────────────────────────────────────────────────
    lines += [
        "## Coverage Notes",
        "",
        coverage_notes,
        "",
    ]

    return "\n".join(lines)
