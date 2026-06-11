"""
Evaluator agent.

Quality gate for the risk findings produced by the scan agents.
This agent enforces the evidence-integrity rule: it may only

    ACCEPT   — include a finding in the final report as-is
    REJECT   — drop a finding (low confidence, missing evidence, or duplicate)
    MERGE    — keep the highest-severity finding when two findings share the
               same (file, line_range, risk_type) and drop the rest
    RERUN    — signal that one or more risk categories should be re-scanned
               (e.g., no findings for a category that the profile flagged)

The evaluator NEVER rewrites evidence, attack_path, or any other content field.
All decisions are expressed as ID lists in EvalResult.
"""

from __future__ import annotations

from collections import defaultdict

from mcp_security_agent.schemas import EvalResult, RiskFinding


# Minimum confidence for a finding to be accepted
CONFIDENCE_THRESHOLD = 0.55

# Severity order for merge decisions (higher index = higher severity)
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def evaluate_findings(
    findings: list[RiskFinding],
    expected_categories: list[str] | None = None,
) -> EvalResult:
    """
    Evaluate a list of RiskFindings and return an EvalResult.

    Parameters
    ----------
    findings:
        All findings produced so far by scan agents.
    expected_categories:
        Risk categories the supervisor intended to scan (from ScanConfig).
        If provided, the evaluator checks for coverage gaps and may request a rerun.
    """
    accepted_ids: list[str] = []
    rejected_ids: list[str] = []
    merged_ids: list[str] = []          # IDs that were folded into a surviving finding
    rerun_categories: list[str] = []
    rejection_reasons: list[str] = []

    # ── Step 1: reject findings below confidence threshold or missing evidence ──
    passing: list[RiskFinding] = []
    for f in findings:
        if f.confidence < CONFIDENCE_THRESHOLD:
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(
                f"[{f.finding_id}] rejected: confidence {f.confidence:.2f} < {CONFIDENCE_THRESHOLD}"
            )
        elif not f.evidence or not f.evidence.strip():
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(f"[{f.finding_id}] rejected: empty evidence")
        elif not f.attack_path or not f.attack_path.strip():
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(f"[{f.finding_id}] rejected: missing attack_path")
        else:
            passing.append(f)

    # ── Step 2: merge duplicates (same file + line_range + risk_type) ──
    # Group by dedup key, keep the highest-severity finding in each group
    dedup_key = lambda f: (f.file_path, f.line_range, f.risk_type)  # noqa: E731
    groups: dict[tuple, list[RiskFinding]] = defaultdict(list)
    for f in passing:
        groups[dedup_key(f)].append(f)

    surviving: list[RiskFinding] = []
    for group in groups.values():
        if len(group) == 1:
            surviving.append(group[0])
        else:
            # Keep highest severity; if tied, keep highest confidence
            best = max(group, key=lambda f: (_SEVERITY_ORDER[f.severity], f.confidence))
            surviving.append(best)
            # Everything else in this group is merged (not rejected)
            for f in group:
                if f.finding_id != best.finding_id:
                    merged_ids.append(f.finding_id)

    # ── Step 3: accept the surviving set ──
    accepted_ids = [f.finding_id for f in surviving]

    # ── Step 4: check coverage gaps ──
    if expected_categories:
        found_types = {f.risk_type for f in surviving}
        # Map category names (from ScanConfig) to risk_type values in RiskFinding
        category_to_type = {
            "prompt_injection": "prompt_injection",
            "command_exec": "command_exec",
            "file_access": "file_access",
            "network": "network_ssrf",
            "lifecycle": "lifecycle_leak",
        }
        for cat in expected_categories:
            rt = category_to_type.get(cat)
            if rt and rt not in found_types:
                rerun_categories.append(cat)

    needs_rerun = bool(rerun_categories)

    # ── Step 5: build risk summary over accepted findings ──
    risk_summary: dict[str, int] = {}
    for f in surviving:
        risk_summary[f.severity] = risk_summary.get(f.severity, 0) + 1

    overall_confidence = (
        sum(f.confidence for f in surviving) / len(surviving)
        if surviving else 0.0
    )

    notes_parts = []
    if rejection_reasons:
        notes_parts.append("Rejections: " + "; ".join(rejection_reasons))
    if merged_ids:
        notes_parts.append(f"Merged {len(merged_ids)} duplicate finding(s).")
    if rerun_categories:
        notes_parts.append(f"Coverage gap — requesting rerun for: {rerun_categories}.")
    if not notes_parts:
        notes_parts.append("All findings passed quality checks.")

    return EvalResult(
        accepted=bool(accepted_ids) or not findings,
        overall_confidence=round(overall_confidence, 3),
        missing_categories=rerun_categories,
        needs_rerun=needs_rerun,
        rerun_categories=rerun_categories,
        accepted_finding_ids=accepted_ids,
        rejected_finding_ids=rejected_ids,
        merged_finding_ids=merged_ids,
        risk_summary=risk_summary,
        evaluator_notes=" | ".join(notes_parts),
    )
