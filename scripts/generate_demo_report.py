"""Generate the demo report published on the website (docs/).

Scans ONLY sample_mcp_server/ — the deliberately vulnerable demo target —
so the published report contains no findings from our own test fixtures.

Outputs:
  docs/data/demo_report.json   structured data the website renders
  results/demo_report_<ts>.md  human-readable copy for the archive (gitignored)

Run from the repo root. With a key in .env you get the LLM-polished
executive summary + blind re-judgment + embedding-based RAG references;
without one, everything falls back to deterministic mode (still works).

    python3 -m scripts.generate_demo_report
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from mcp_security_agent.graph import app
from mcp_security_agent.schemas import GraphState, ScanRequest, ScanConfig

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sample_mcp_server"
OUT_JSON = ROOT / "docs" / "data" / "demo_report.json"


def main() -> int:
    if not TARGET.is_dir():
        print(f"Demo target not found: {TARGET}", file=sys.stderr)
        return 1

    state = GraphState(
        scan_request=ScanRequest(
            project_path=str(TARGET),
            config=ScanConfig(scan_depth="standard"),
        )
    )
    result = app.invoke(state)

    report = result.get("final_report")
    if report is None:
        print("Pipeline finished without a final report — aborting.", file=sys.stderr)
        return 1

    # References live in GraphState.rag_contexts, keyed by finding_id.
    # Export only what the website needs (title + source URL), not full doc text.
    references: dict[str, list[dict[str, str]]] = {}
    for ctx in result.get("rag_contexts", []):
        references[ctx.finding_id] = [
            {"title": d.title, "source": d.source} for d in ctx.documents
        ]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": "sample_mcp_server",
        "overall_risk_level": report.overall_risk_level,
        "executive_summary": report.executive_summary,
        "coverage_notes": report.coverage_notes,
        "action_plan": report.action_plan,
        "findings": [f.model_dump(mode="json") for f in report.accepted_findings],
        "references": references,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"Wrote {OUT_JSON.relative_to(ROOT)}  ({len(payload['findings'])} findings)")

    # Markdown copy for the archive, same convention as graph.py's entry point.
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    md_path = ROOT / "results" / f"demo_report_{stamp}.md"
    md_path.parent.mkdir(exist_ok=True)
    md_path.write_text(report.report_markdown)
    print(f"Wrote {md_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
