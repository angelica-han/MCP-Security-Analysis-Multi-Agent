"""
knowledge_retriever.py — RAG retrieval over the local knowledge base.

Runs after the Evaluator (accepted findings only). For each finding it builds
a query from the finding's own fields (agentic RAG: the "question" comes from
pipeline state, not a user), retrieves the most relevant knowledge-base
documents, and returns RagContext objects the Reporter can cite.

Backend selection (same no-key-fallback philosophy as llm.py):
  1. OPENAI_API_KEY present and chromadb importable
       → OpenAI embeddings + in-memory Chroma (semantic vectors)
  2. otherwise, scikit-learn importable
       → TF-IDF + cosine similarity (deterministic, offline)
  3. otherwise → no retrieval; pipeline continues with empty contexts

Documents whose distance exceeds MAX_DISTANCE are dropped rather than
attached: a finding with no relevant reference gets none (evidence-first —
never cite a document that doesn't actually match).
"""

import os
import re
from pathlib import Path
from typing import Callable, Optional

from mcp_security_agent.schemas import RagContext, RagDocument, RiskFinding

# knowledge_base/ lives at the project root, next to mcp_security_agent/
KB_DIR = Path(__file__).resolve().parents[2] / "knowledge_base"

EMBED_MODEL = "text-embedding-3-small"
TOP_K = 2               # documents attached per finding
MAX_DISTANCE = {        # per-backend relevance cutoff (tuning knob — distances
    "openai": 0.90,     # are NOT comparable across backends)
    "tfidf": 0.95,
}


# ─────────────────────────────────────────────
# Knowledge-base loading
# ─────────────────────────────────────────────

def load_kb_documents(kb_dir: Path = KB_DIR) -> list[RagDocument]:
    """Parse each knowledge_base/*.md (frontmatter + body) into a RagDocument."""
    docs: list[RagDocument] = []
    if not kb_dir.is_dir():
        return docs
    for path in sorted(kb_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        if not match:
            continue
        frontmatter, body = match.groups()
        meta = {}
        for line in frontmatter.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                meta[key.strip()] = value.strip().strip('"')
        docs.append(RagDocument(
            doc_id=meta.get("doc_id", path.stem),
            title=meta.get("title", path.stem),
            source=meta.get("source", ""),
            risk_type=meta.get("risk_type", ""),
            content=body.strip(),
        ))
    return docs


# ─────────────────────────────────────────────
# Retrieval backends
# Each builder returns retrieve(query, k) -> list[RagDocument with distance],
# or None if the backend is unavailable.
# ─────────────────────────────────────────────

def _build_openai_chroma(docs: list[RagDocument]) -> Optional[Callable]:
    if not os.environ.get("OPENAI_API_KEY"):
        return None
    try:
        import chromadb
        from chromadb.utils import embedding_functions

        embedder = embedding_functions.OpenAIEmbeddingFunction(
            api_key=os.environ["OPENAI_API_KEY"], model_name=EMBED_MODEL
        )
        client = chromadb.Client()
        # get_or_create + upsert (not create + add): chromadb.Client() shares
        # one in-process system, so a second retrieval in the same process
        # (e.g. the eval harness invoking the pipeline once per labeled case)
        # would otherwise hit "collection already exists" and silently
        # degrade to the TF-IDF fallback.
        collection = client.get_or_create_collection(
            "knowledge_base", embedding_function=embedder
        )
        collection.upsert(
            ids=[d.doc_id for d in docs],
            documents=[d.content for d in docs],
        )
    except Exception as exc:                       # import error, network, quota…
        print(f"   ⚠️  OpenAI/Chroma backend unavailable ({type(exc).__name__}); trying TF-IDF")
        return None

    by_id = {d.doc_id: d for d in docs}

    def retrieve(query: str, k: int) -> list[RagDocument]:
        res = collection.query(query_texts=[query], n_results=k)
        out = []
        for doc_id, dist in zip(res["ids"][0], res["distances"][0]):
            if dist <= MAX_DISTANCE["openai"]:
                out.append(by_id[doc_id].model_copy(update={"distance": round(float(dist), 4)}))
        return out

    return retrieve


def _build_tfidf(docs: list[RagDocument]) -> Optional[Callable]:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        return None

    vectorizer = TfidfVectorizer(stop_words="english")
    doc_matrix = vectorizer.fit_transform([d.content for d in docs])

    def retrieve(query: str, k: int) -> list[RagDocument]:
        sims = cosine_similarity(vectorizer.transform([query]), doc_matrix)[0]
        out = []
        for i in sims.argsort()[::-1][:k]:
            dist = 1.0 - float(sims[i])            # distance = 1 - cosine_sim
            if dist <= MAX_DISTANCE["tfidf"]:
                out.append(docs[i].model_copy(update={"distance": round(dist, 4)}))
        return out

    return retrieve


# ─────────────────────────────────────────────
# Public API — called by the graph's rag node
# ─────────────────────────────────────────────

def build_query(finding: RiskFinding) -> str:
    """The finding IS the question: risk type + attack path + evidence code.
    The evidence snippet carries the signal that discriminates between
    sub-pattern documents within the same risk class."""
    return f"{finding.risk_type}: {finding.attack_path}\n{finding.evidence}"


def retrieve_contexts(
    findings: list[RiskFinding],
    kb_dir: Path = KB_DIR,
    k: int = TOP_K,
) -> list[RagContext]:
    """Retrieve knowledge-base references for each accepted finding.

    Never raises: on any backend failure the affected findings simply get
    empty document lists, and the pipeline continues.
    """
    docs = load_kb_documents(kb_dir)
    if not docs:
        print("   ⚠️  knowledge_base/ empty or missing — skipping retrieval")
        return []

    retrieve = _build_openai_chroma(docs)
    backend = "openai"
    if retrieve is None:
        retrieve = _build_tfidf(docs)
        backend = "tfidf"
    if retrieve is None:
        print("   ⚠️  No retrieval backend available — skipping retrieval")
        return []
    print(f"   Retrieval backend: {backend} | {len(docs)} document(s) indexed")

    contexts = []
    for finding in findings:
        query = build_query(finding)
        try:
            documents = retrieve(query, k)
        except Exception as exc:
            print(f"   ⚠️  Retrieval failed for {finding.finding_id} ({type(exc).__name__})")
            documents = []
        contexts.append(RagContext(
            finding_id=finding.finding_id,
            query=query,
            documents=documents,
        ))
    return contexts
