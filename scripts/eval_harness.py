"""
eval_harness.py — Labeled-case evaluation harness.

Runs the full pipeline on each labeled fixture case (tests/fixtures/labels.jsonl),
grades the accepted findings against the case's ground truth, and reports
precision / recall / false-positive stats — overall, per risk type, and on the
hard-negative cases specifically.

Usage (from the project root):
    python3 -m scripts.eval_harness            # LLM mode (uses .env keys)
    python3 -m scripts.eval_harness --no-llm   # deterministic baseline

Grading rules:
- Findings are graded AFTER the evaluator gate (accepted findings only) —
  we measure the system's final output, not raw agent chatter.
- Scope: only findings whose risk_type belongs to the case's declared scope
  (scan_categories + every type mentioned in expected/absent) are graded.
  Out-of-scope findings are recorded but not counted — no ground truth there.
- An expected_finding matches an accepted finding when risk_type is equal,
  file_path matches on the tail, and every evidence_contains substring is
  present in the finding's evidence. Matched = TP, unmatched expected = FN.
- Any in-scope finding of an expected_absent type = FP (hard-negative miss).
- Any in-scope finding matching nothing = FP (shotgun penalty).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field

# ── 0. CLI + LLM kill-switch ─────────────────────────────────────────────
# This must happen BEFORE importing the pipeline: llm.py calls load_dotenv()
# at import time. load_dotenv never overrides variables that already exist,
# so setting LLM_MODEL here wins over .env. "disabled:none" is not a real
# provider — init_chat_model raises immediately and get_llm() returns None,
# which flips every LLM call site to its deterministic fallback.
parser = argparse.ArgumentParser(description="Run labeled-case evaluation.")
parser.add_argument("--no-llm", action="store_true",
                    help="Force deterministic mode (baseline).")
parser.add_argument("--labels", default="tests/fixtures/labels.jsonl",
                    help="Path to the labels file.")
args = parser.parse_args()

if args.no_llm:
    os.environ["LLM_MODEL"] = "disabled:none"

from mcp_security_agent.graph import app                      # noqa: E402
from mcp_security_agent.schemas import (                      # noqa: E402
    GraphState,
    RiskFinding,
    ScanConfig,
    ScanRequest,
)

# scan_categories (config names) → risk_type (finding names).
# The two vocabularies differ for two categories; labels use both.
CATEGORY_TO_RISK_TYPE = {
    "prompt_injection": "prompt_injection",
    "command_exec": "command_exec",
    "file_access": "file_access",
    "network": "network_ssrf",
    "lifecycle": "lifecycle_leak",
}


# ── 1. Run the pipeline on a single case ─────────────────────────────────
def run_case(case: dict) -> list[RiskFinding]:
    """
    Invoke the full graph with the case directory as the scan target and
    return the accepted findings (post-evaluator). Each case is a tiny
    self-contained project, so this is an isolated, clean-room run.
    """
    state = GraphState(
        scan_request=ScanRequest(
            project_path=os.path.abspath(case["project_path"]),
            config=ScanConfig(scan_depth="quick", max_files=10),
        )
    )
    result = app.invoke(state)
    return result["risk_findings"]


# ── 2. Grade one case against its labels ─────────────────────────────────
@dataclass
class CaseResult:
    case_id: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    is_hard_negative: bool = False      # case with expected_absent entries
    absent_violated: bool = False       # reported a type it was told not to
    fp_details: list[str] = field(default_factory=list)
    fn_details: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)


def _in_scope_types(case: dict) -> set[str]:
    """Risk types this case has ground truth for. Everything else is out
    of scope: we refuse to grade what the label doesn't annotate."""
    scope = {CATEGORY_TO_RISK_TYPE[c] for c in case["scan_categories"]}
    scope |= {e["risk_type"] for e in case["expected_findings"]}
    scope |= set(case["expected_absent"])
    return scope


def _matches(expected: dict, finding: RiskFinding) -> bool:
    """The agreed matching rule: same type, tail-matching path, and every
    evidence_contains substring present in the finding's evidence.
    Content-anchored on purpose — line numbers depend on which scanner
    produced the feature, evidence text does not."""
    if finding.risk_type != expected["risk_type"]:
        return False
    if not finding.file_path.endswith(expected["file_path"]):
        return False
    return all(s in finding.evidence for s in expected["evidence_contains"])


def grade_case(case: dict, findings: list[RiskFinding]) -> CaseResult:
    scope = _in_scope_types(case)
    res = CaseResult(
        case_id=case["case_id"],
        is_hard_negative=bool(case["expected_absent"]),
    )

    in_scope, matched_ids = [], set()
    for f in findings:
        if f.risk_type in scope:
            in_scope.append(f)
        else:
            res.out_of_scope.append(f"{f.risk_type} @ {f.file_path}")

    # Expected findings: greedy 1-to-1 matching. Each expected consumes at
    # most one finding, so five shotgun copies can't all ride one answer.
    for expected in case["expected_findings"]:
        hit = next(
            (f for f in in_scope
             if f.finding_id not in matched_ids and _matches(expected, f)),
            None,
        )
        if hit:
            res.tp += 1
            matched_ids.add(hit.finding_id)
        else:
            res.fn += 1
            res.fn_details.append(
                f"missed {expected['risk_type']} "
                f"(needs {expected['evidence_contains']})"
            )

    # Every unmatched in-scope finding is a false positive; if its type is
    # on the expected_absent list, it's specifically a hard-negative miss.
    for f in in_scope:
        if f.finding_id in matched_ids:
            continue
        res.fp += 1
        res.fp_details.append(f"{f.risk_type} @ {f.file_path}:{f.line_range}")
        if f.risk_type in case["expected_absent"]:
            res.absent_violated = True

    return res


# ── 3. Summarize across all cases ────────────────────────────────────────
def summarize(results: list[CaseResult], mode: str) -> dict:
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    fn = sum(r.fn for r in results)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    hard = [r for r in results if r.is_hard_negative]
    hard_missed = [r.case_id for r in hard if r.absent_violated]

    print()
    print("=" * 62)
    print(f"📊 Eval summary — mode: {mode}")
    print("=" * 62)
    print(f"{'case':<48} TP FP FN")
    for r in results:
        flag = " ❌" if r.absent_violated else ""
        print(f"{r.case_id:<48} {r.tp:>2} {r.fp:>2} {r.fn:>2}{flag}")
        for d in r.fp_details:
            print(f"     FP: {d}")
        for d in r.fn_details:
            print(f"     FN: {d}")
        for d in r.out_of_scope:
            print(f"     out-of-scope (ungraded): {d}")
    print("-" * 62)
    print(f"precision {precision:.3f}   recall {recall:.3f}   F1 {f1:.3f}"
          f"   (TP {tp} / FP {fp} / FN {fn})")
    print(f"hard negatives: {len(hard_missed)}/{len(hard)} false-alarmed"
          + (f" → {', '.join(hard_missed)}" if hard_missed else " 🎉"))

    return {
        "mode": mode,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": tp, "fp": fp, "fn": fn,
        "hard_negative_total": len(hard),
        "hard_negative_false_alarms": hard_missed,
        "cases": [vars(r) for r in results],
    }


# ── 4. Main ──────────────────────────────────────────────────────────────
def main() -> None:
    mode = "deterministic" if args.no_llm else "llm"
    with open(args.labels) as fh:
        cases = [json.loads(line) for line in fh if line.strip()]
    print(f"🧪 {len(cases)} labeled case(s), mode: {mode}")

    results = []
    for i, case in enumerate(cases, 1):
        print(f"\n──── [{i}/{len(cases)}] {case['case_id']} ────")
        try:
            findings = run_case(case)
        except Exception as e:  # one broken case shouldn't sink the run
            print(f"   💥 pipeline error: {e}", file=sys.stderr)
            findings = []
        results.append(grade_case(case, findings))

    summary = summarize(results, mode)

    os.makedirs("results", exist_ok=True)
    from datetime import datetime
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_path = f"results/eval_{mode}_{stamp}.json"
    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
