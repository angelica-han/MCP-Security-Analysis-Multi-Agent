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

The evaluator NEVER rewrites evidence, attack_path, or any other *fact* field.
It MAY revise a finding's `confidence` — but only via an independent LLM second
opinion on low-confidence findings (see llm_evaluator.py), preserving the
original score in `agent_confidence`. Facts stay immutable; only the judgment
(confidence) can change. Accept/reject/merge are still expressed as ID lists.
"""

from __future__ import annotations

import os
from collections import defaultdict

from mcp_security_agent.agents.llm_evaluator import LLMEvaluator
from mcp_security_agent.schemas import AgentDivergence, EvalResult, RiskFinding


# Minimum confidence for a finding to be accepted
CONFIDENCE_THRESHOLD = 0.55

# Findings below this confidence get a blind LLM second opinion (the "uncertain
# band"). Above it the agent is confident enough that we don't spend an LLM call.
# Below 0.55 → rescue under-scored real risks; 0.55–0.7 → double-check borderline
# accepts for false positives.
LLM_REJUDGE_BELOW = 0.7

# Lines of surrounding source code handed to the LLM around a finding.
_SOURCE_CONTEXT_PAD = 6

# Severity order for merge decisions (higher index = higher severity)
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Two findings in the same file with the same risk_type are considered duplicates
# if their line ranges are within this many lines of each other
_LINE_PROXIMITY_TOLERANCE = 10


def _ranges_are_close(r1: tuple[int, int], r2: tuple[int, int], tolerance: int = _LINE_PROXIMITY_TOLERANCE) -> bool:
    """
    Return True if two line ranges overlap or are within `tolerance` lines of each other.
    e.g. (10, 15) and (20, 25) with tolerance=10 → True (gap is 5)
         (10, 15) and (30, 35) with tolerance=10 → False (gap is 15)
    """
    return r1[0] - tolerance <= r2[1] and r2[0] - tolerance <= r1[1]


def _cluster_by_proximity(findings: list[RiskFinding]) -> list[list[RiskFinding]]:
    """
    Group findings into clusters where every member is "close" to the seed finding.
    Simple greedy approach: good enough for the small lists we deal with.
    """
    clusters: list[list[RiskFinding]] = []
    used = [False] * len(findings)
    for i, seed in enumerate(findings):
        if used[i]:
            continue
        cluster = [seed]
        used[i] = True
        for j, other in enumerate(findings):
            if used[j]:
                continue
            if _ranges_are_close(seed.line_range, other.line_range):
                cluster.append(other)
                used[j] = True
        clusters.append(cluster)
    return clusters


def _read_source_context(
    project_path: str,
    file_path: str,
    line_range: tuple[int, int],
    pad: int = _SOURCE_CONTEXT_PAD,
) -> str:
    """
    Read the finding's lines plus `pad` lines of surrounding context from the
    real source file, with line numbers. Returns "" if the file can't be read
    (the caller then keeps the agent's score rather than guessing).
    """
    path = os.path.join(project_path, file_path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""

    start = max(0, line_range[0] - 1 - pad)
    end = min(len(lines), line_range[1] + pad)
    return "\n".join(f"{i + 1:4d}  {lines[i].rstrip()}" for i in range(start, end))


def _aggregate_divergence(
    records: list[tuple[str, float, float]],
) -> list[AgentDivergence]:
    """
    Aggregate (risk_type, agent_conf, llm_conf) records into per-risk_type stats.

    likely_false_positive = the agent scored it acceptable (>= threshold) but the
    LLM's independent read scored it below threshold — a false positive the agent
    would otherwise have let through.
    """
    by_type: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for risk_type, agent_c, llm_c in records:
        by_type[risk_type].append((agent_c, llm_c))

    out: list[AgentDivergence] = []
    for risk_type, pairs in by_type.items():
        deltas = [abs(a - l) for a, l in pairs]
        out.append(
            AgentDivergence(
                risk_type=risk_type,
                rejudged_count=len(pairs),
                over_0_2=sum(1 for d in deltas if d > 0.2),
                over_0_3=sum(1 for d in deltas if d > 0.3),
                likely_false_positives=sum(
                    1 for a, l in pairs if a >= CONFIDENCE_THRESHOLD and l < CONFIDENCE_THRESHOLD
                ),
                mean_abs_delta=round(sum(deltas) / len(deltas), 3) if deltas else 0.0,
            )
        )
    return out


def evaluate_findings(
    findings: list[RiskFinding],
    expected_categories: list[str] | None = None,
    project_path: str | None = None,
    use_llm: bool = True,
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
    project_path:
        Project root, used to read source code for the LLM second opinion.
        If None, the LLM re-judgment step is skipped (rule-based behaviour only).
    use_llm:
        If True (default), low-confidence findings get a blind LLM re-score.
        Set False to force pure rule-based evaluation (tests / reproducibility).
    """
    accepted_ids: list[str] = []
    rejected_ids: list[str] = []
    merged_ids: list[str] = []          # IDs that were folded into a surviving finding
    rerun_categories: list[str] = []
    rejection_reasons: list[str] = []
    divergence_records: list[tuple[str, float, float]] = []  # (risk_type, agent_conf, llm_conf)

    # ── Step 1a: drop structural junk (no evidence / no attack_path) FIRST ──
    # We never spend an LLM call on — or let it fabricate evidence for — junk.
    candidates: list[RiskFinding] = []
    for f in findings:
        if not f.evidence or not f.evidence.strip():
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(f"[{f.finding_id}] rejected: empty evidence")
        elif not f.attack_path or not f.attack_path.strip():
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(f"[{f.finding_id}] rejected: missing attack_path")
        else:
            candidates.append(f)

    # ── Step 1b: blind LLM second opinion on the uncertain band ──
    # For findings the agents were unsure about (confidence < LLM_REJUDGE_BELOW),
    # an LLM re-reads the real source code and issues its OWN score, blind to the
    # agent's verdict. We store the original in agent_confidence and use the LLM's
    # score as the effective confidence for the accept/reject decision below.
    if use_llm and project_path:
        llm_ev = LLMEvaluator()
        if llm_ev.available:
            for f in candidates:
                if f.confidence >= LLM_REJUDGE_BELOW:
                    continue
                context = _read_source_context(project_path, f.file_path, f.line_range)
                if not context:
                    continue
                result = llm_ev.rejudge(f.risk_type, context)
                if result is None:
                    continue  # LLM failed → keep the agent's score
                llm_conf, reason = result
                f.agent_confidence = f.confidence  # preserve the original
                f.llm_confidence = llm_conf
                f.llm_rationale = reason
                f.confidence = llm_conf            # effective score becomes the LLM's
                divergence_records.append((f.risk_type, f.agent_confidence, llm_conf))

    # ── Step 1c: confidence threshold on the (possibly LLM-updated) score ──
    passing: list[RiskFinding] = []
    for f in candidates:
        if f.confidence < CONFIDENCE_THRESHOLD:
            rejected_ids.append(f.finding_id)
            rejection_reasons.append(
                f"[{f.finding_id}] rejected: confidence {f.confidence:.2f} < {CONFIDENCE_THRESHOLD}"
            )
        else:
            passing.append(f)

    # ── Step 2: merge duplicates (same file + risk_type + nearby lines) ──
    # First group by (file_path, risk_type), then cluster by line proximity within each group.
    # This handles cases where two agents flag the same vulnerability but report slightly
    # different line ranges (e.g. "10-15" vs "10-20").
    by_type: dict[tuple, list[RiskFinding]] = defaultdict(list)
    for f in passing:
        by_type[(f.file_path, f.risk_type)].append(f)

    surviving: list[RiskFinding] = []
    for type_group in by_type.values():
        for cluster in _cluster_by_proximity(type_group):
            if len(cluster) == 1:
                surviving.append(cluster[0])
            else:
                # Keep highest severity; if tied, keep highest confidence
                best = max(cluster, key=lambda f: (_SEVERITY_ORDER[f.severity], f.confidence))
                surviving.append(best)
                for f in cluster:
                    if f.finding_id != best.finding_id:
                        merged_ids.append(f.finding_id)

    # ── Step 3: accept the surviving set ──
    accepted_ids = [f.finding_id for f in surviving]

    # ── Step 4: check coverage gaps ──
    # Low-signal categories are excluded from rerun logic because finding nothing
    # is a legitimate outcome (not a scan failure worth retrying).
    _NO_RERUN_CATEGORIES = {"lifecycle"}

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
            if cat in _NO_RERUN_CATEGORIES:
                continue
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

    # ── Step 6: aggregate the agent-vs-LLM divergence signal ──
    divergence_by_type = _aggregate_divergence(divergence_records)

    notes_parts = []
    if rejection_reasons:
        notes_parts.append("Rejections: " + "; ".join(rejection_reasons))
    if merged_ids:
        notes_parts.append(f"Merged {len(merged_ids)} duplicate finding(s).")
    if divergence_records:
        notes_parts.append(f"LLM re-judged {len(divergence_records)} low-confidence finding(s).")
    if rerun_categories:
        notes_parts.append(f"Coverage gap — requesting rerun for: {rerun_categories}.")
    if not notes_parts:
        notes_parts.append("All findings passed quality checks.")

    return EvalResult(
        accepted=bool(accepted_ids),   # True only if at least one finding was accepted
        pipeline_ok=True,              # evaluator completed successfully regardless
        overall_confidence=round(overall_confidence, 3),
        missing_categories=rerun_categories,
        needs_rerun=needs_rerun,
        rerun_categories=rerun_categories,
        accepted_finding_ids=accepted_ids,
        rejected_finding_ids=rejected_ids,
        merged_finding_ids=merged_ids,
        risk_summary=risk_summary,
        evaluator_notes=" | ".join(notes_parts),
        llm_rejudged_count=len(divergence_records),
        divergence_by_type=divergence_by_type,
    )
