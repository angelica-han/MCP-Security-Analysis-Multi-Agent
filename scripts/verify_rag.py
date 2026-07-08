"""RAG retrieval verification — exercises the real knowledge_retriever module.

Builds three simulated RiskFindings (one per risk class), runs them through
mcp_security_agent.tools.knowledge_retriever.retrieve_contexts (the same code
path the graph's rag node uses), and grades the result:
PASS = the top-1 retrieved document's risk_type matches the finding's.

Run:  python3 -m scripts.verify_rag           # OpenAI embeddings + Chroma
      python3 -m scripts.verify_rag --tfidf   # force the deterministic fallback
"""

import argparse
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from mcp_security_agent.schemas import RiskFinding
from mcp_security_agent.tools.knowledge_retriever import (
    load_kb_documents,
    retrieve_contexts,
)


def _finding(fid: str, risk_type: str, evidence: str, attack_path: str) -> RiskFinding:
    """Minimal valid RiskFinding for retrieval testing."""
    return RiskFinding(
        finding_id=fid,
        risk_type=risk_type,
        severity="high",
        confidence=0.9,
        file_path="simulated.py",
        line_range=(1, 3),
        evidence=evidence,
        attack_path=attack_path,
        impact="simulated",
        remediation="simulated",
    )


SIMULATED_FINDINGS = [
    _finding(
        "sim-cmd-01", "command_exec",
        'subprocess.run(f"git log {branch_name}", shell=True)',
        "tool parameter branch_name → f-string → subprocess.run(shell=True)",
    ),
    _finding(
        "sim-file-01", "file_access",
        'open(os.path.join(BASE_DIR, request.params["path"])).read()',
        "user-supplied path → os.path.join → open() without containment check",
    ),
    _finding(
        "sim-pi-01", "prompt_injection",
        'prompt = f"Summarize this page: {fetched_html}"',
        "remote web content → f-string → LLM prompt",
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tfidf", action="store_true",
        help="force the deterministic TF-IDF backend (no API key / network)",
    )
    args = parser.parse_args()
    if args.tfidf:
        os.environ.pop("OPENAI_API_KEY", None)   # this process only

    docs = load_kb_documents()
    print(f"Loaded {len(docs)} knowledge base documents:")
    for d in docs:
        print(f"  [{d.risk_type:>16}] {d.doc_id}  {d.title}")
    print()

    contexts = retrieve_contexts(SIMULATED_FINDINGS, k=3)
    print()

    by_id = {c.finding_id: c for c in contexts}
    all_pass = True

    for finding in SIMULATED_FINDINGS:
        ctx = by_id.get(finding.finding_id)
        print(f"Finding {finding.finding_id} ({finding.risk_type})")
        print(f"  evidence: {finding.evidence}")
        if not ctx or not ctx.documents:
            all_pass = False
            print("  ❌ FAIL — no documents retrieved\n")
            continue
        for rank, doc in enumerate(ctx.documents, 1):
            marker = "→" if rank == 1 else " "
            print(f"  {marker} #{rank} dist={doc.distance:.4f}  [{doc.risk_type}] {doc.title}")
        ok = ctx.documents[0].risk_type == finding.risk_type
        all_pass &= ok
        print(f"  {'✅ PASS' if ok else '❌ FAIL'} — top-1 is "
              f"{'the matching' if ok else 'a NON-matching'} risk type\n")

    print("=" * 60)
    print("✅ All retrievals matched." if all_pass else "❌ Some retrievals missed — inspect above.")


if __name__ == "__main__":
    main()
