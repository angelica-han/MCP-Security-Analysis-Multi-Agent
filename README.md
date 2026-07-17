# MCP Security Analysis Multi-Agent

A LangGraph-powered multi-agent system that analyzes MCP (Model Context Protocol) project directories for security vulnerabilities and generates evidence-backed reports.

---

## What It Does

Point it at any MCP server/client project directory, and it will:

1. **Scan the directory** — inventory all source files and filter out noise
2. **Profile the project** — understand what MCP capabilities it exposes and where the trust boundaries are
3. **Extract code features** — use static analysis (AST + regex) to find dangerous patterns like shell calls, file access, and network requests
4. **Run risk agents** — five specialized agents scan for different vulnerability classes (prompt injection, command execution, file access, network/SSRF, lifecycle)
5. **Evaluate quality** — an Evaluator checks that every finding has real evidence and merges duplicates; low-confidence findings get a blind LLM second opinion (an independent re-read of the source code) and are rescued or demoted accordingly
6. **Retrieve references (RAG)** — each accepted finding is used as a query against a curated security knowledge base (CWE / OWASP / MCP guidance); relevant documents are attached so remediation advice is traceable to authoritative sources
7. **Generate a report** — structured Markdown + JSON output with evidence chains, attack paths, remediation suggestions, and per-finding references

## Risk Categories

| Agent | What It Looks For |
|---|---|
| Prompt Injection | User/remote content entering system prompts or tool descriptions |
| Command Execution | `shell=True`, command concatenation, unvalidated parameters |
| File Access | Path traversal, sensitive directory reads, missing allowlists |
| Network Request | SSRF, arbitrary URLs, internal network access |
| Lifecycle | Session state leakage, incomplete cleanup, log leakage |

## Tech Stack

- **LangGraph** — multi-agent orchestration (StateGraph, conditional routing, feedback loops)
- **Pydantic** — typed schemas for all inter-agent data; prevents hallucinated evidence
- **Python AST module** — deterministic code feature extraction (no LLM guessing)
- **LangChain LLM layer** — a pluggable chat model via `init_chat_model` (OpenAI / Anthropic / Google, switchable from `.env`). Used in three places: the reporter's **executive summary**, the evaluator's **blind second opinion** on low-confidence findings, and the **prompt-injection agent's** semantic judgment (does untrusted input really reach a prompt?). Every use is grounded in real code/facts and falls back to deterministic logic when no key is configured. The other risk scanners (command / file / network / lifecycle) stay fully deterministic (AST + regex).
- **RAG retrieval layer (Chroma + OpenAI embeddings)** — accepted findings are matched against a curated knowledge base (`knowledge_base/`, CWE / OWASP source material) and the report cites the retrieved references per finding. Agentic RAG: the query is built from the finding's own fields (risk type + attack path + evidence), since no user question exists. Falls back to deterministic TF-IDF retrieval (scikit-learn) when no key is configured; with no backend at all, the pipeline still runs and simply attaches no references.

## Project Structure

```
mcp_security_agent/
├── schemas.py          # All data structures (GraphState, RiskFinding, etc.)
├── graph.py            # LangGraph graph: nodes, edges, conditional routing
├── llm.py              # Shared LLM access layer (init_chat_model, .env, no-key fallback)
├── cli.py              # Command-line entry point
├── agents/
│   ├── functional.py           # Capability analysis agent
│   ├── risk_prompt_injection.py
│   ├── risk_command.py
│   ├── risk_file.py
│   ├── risk_network.py
│   ├── risk_lifecycle.py
│   ├── evaluator.py
│   ├── llm_evaluator.py        # Blind LLM second opinion on low-confidence findings
│   └── reporter.py
└── tools/
    ├── file_inventory.py       # Directory walker and file filter
    ├── ast_scanner.py          # Python AST-based feature extraction
    ├── regex_scanner.py        # Pattern matching for JS/TS and config files
    └── knowledge_retriever.py  # RAG retrieval: finding -> knowledge-base references
knowledge_base/         # Curated security reference docs (CWE / OWASP), one per risk class
scripts/
├── generate_labeled_fixtures.py  # Regenerates the labeled eval cases (source of truth)
├── hard_negative_cases.py        # 7 hard negatives: look dangerous but actually safe
├── eval_harness.py               # Runs every labeled case, grades against ground truth
├── verify_rag.py                 # Retrieval smoke test: simulated findings vs knowledge base
└── generate_demo_report.py       # Scans sample_mcp_server, exports docs/data/demo_report.json
docs/                   # Project website (GitHub Pages): static page rendering the demo report
results/                # Output reports + eval JSONs land here (gitignored)
sample_mcp_server/      # Deliberately vulnerable MCP server used as scan target
tests/fixtures/         # Generated labeled cases (gitignored — rebuild via the script)
```

## Quickstart

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full pipeline against the sample vulnerable server
python3 -m mcp_security_agent.graph
```

**The LLM layer is optional.** With no key configured, the entire pipeline runs on deterministic static analysis (AST + regex) and the executive summary falls back to a rule-based template — nothing breaks.

To enable the LLM-polished executive summary, copy `.env.example` to `.env`, add a key for one provider, and set `LLM_MODEL`:

```dotenv
OPENAI_API_KEY=sk-...
LLM_MODEL=openai:gpt-4o-mini
```

Switching providers (OpenAI / Anthropic / Google) is a one-line change to `LLM_MODEL`. `.env` is gitignored — keys never enter the repo.

## RAG Knowledge Base

After the Evaluator accepts findings, a retrieval node (`rag` in the graph)
matches each finding against `knowledge_base/` — curated reference documents
(CWE entries, OWASP guidance) with one document per risk class, tagged with the
same `risk_type` values used by `RiskFinding`. Retrieved references are
rendered as a per-finding **References** section in the report.

Design choices:

- **The finding is the query** (agentic RAG): `risk_type + attack_path +
  evidence` — the evidence snippet carries the signal that will discriminate
  between sub-pattern documents once the knowledge base grows beyond one
  document per class.
- **No chunking yet**: documents are hand-curated at ~300 words, single-topic —
  they are already retrieval-sized. Automatic chunking becomes necessary only
  when ingesting long official texts.
- **Relevance cutoff over forced citations**: documents beyond a distance
  threshold are dropped; a finding with no close reference gets none.
- Verify retrieval quality: `python3 -m scripts.verify_rag` (OpenAI embeddings)
  or `python3 -m scripts.verify_rag --tfidf` (deterministic fallback).

Known limits (deliberate, discussed for next iteration): document content is
curated paraphrase and should move to verbatim official excerpts with per-section
attribution; with one document per class, retrieval is near-trivial — the vector
search earns its keep once each class has multiple sub-pattern documents; the
retrieved content is cited but not yet fed into the LLM prompt for per-finding
remediation narrative (the "G" of RAG is pending the reporter's LLM upgrade).

## Evaluation

The system is measured against 16 labeled fixture cases with ground truth
(`tests/fixtures/labels.jsonl`): 8 positive cases (one typical vulnerability
per risk class) and 8 negative controls, including 7 hard negatives — code
that looks dangerous to pattern-matching but is actually guarded (allowlists,
overwritten parameters, non-prompt strings).

```bash
python3 -m scripts.eval_harness --no-llm   # deterministic baseline
python3 -m scripts.eval_harness            # LLM-integrated mode
```

Each case is scanned in isolation; accepted findings are graded against the
label (matching on risk type, file path, and evidence content — not line
numbers). Every run saves a JSON scorecard to `results/`.

### Results (2026-07-02)

| | Deterministic baseline | LLM-integrated |
|---|---|---|
| Precision | 0.615 | **0.700** |
| Recall | **1.000** | 0.875 |
| F1 | 0.762 | 0.778 |
| Hard-negative false alarms | 5/8 | **3/8** |

What the numbers say:

- **Prompt injection (LLM-backed agent): false positives cleared with zero
  recall loss** — all 3 hard negatives pass, the true injection is still caught.
- The remaining false alarms come from agents that scored their mistakes
  *confidently* (≥ 0.7), bypassing the evaluator's blind-review gate — the
  measured version of the "high-confidence express lane" problem.
- The blind reviewer rescued one lifecycle false positive but also dismissed a
  real log leak: leak-type judgments need context the code window doesn't
  carry. LLM integration helps exactly where the evidence lives in the window.

## Website

`docs/` contains the project website, served via GitHub Pages (Settings → Pages → `main` / `docs`). It is a single static page — no framework, no build step — that renders `docs/data/demo_report.json`: a real pipeline scan of `sample_mcp_server`, exported by:

```bash
python3 -m scripts.generate_demo_report
```

The page renders the pipeline's JSON output unedited (findings, evidence, attack paths, references, action plan). Re-run the script and push to refresh the demo. An upload-and-scan version (dynamic backend, containerized) is planned as phase 2 — the same renderer will display its results.

## Current Status

| Component | Status |
|---|---|
| Project structure | ✅ Done |
| Pydantic schemas | ✅ Done |
| LangGraph graph | ✅ Done — all nodes connected, full pipeline runs end-to-end |
| Directory inventory | ✅ Done |
| Code feature extraction (AST scanner) | ✅ Done |
| Risk agents: command, file, network, prompt injection | ✅ Done — real static-analysis logic |
| Capability analysis agent (`functional.py`) | ✅ Done — rule-based, infers project type + sensitive capabilities from AST features |
| Supervisor routing | ✅ Done — activates only relevant scan categories based on detected capabilities |
| Evaluator agent | ✅ Done — confidence threshold, proximity-based dedup, coverage gap detection, rerun loop |
| Reporter agent | ✅ Done — structured Markdown with severity grouping, action plan (P0/P1/P2), coverage notes |
| Risk agent: lifecycle | ✅ Done — incomplete cleanup, log leakage, session state detection |
| Eval harness (labeled fixtures, precision/recall/FP) | ✅ Done — 16 labeled cases (8 positive + 8 negative controls incl. 7 hard negatives); deterministic-vs-LLM scorecard saved per run |
| Project website (`docs/`, GitHub Pages) | ✅ Done — static single-page site rendering a real demo scan; upload-and-scan (dynamic, containerized) planned as phase 2 |
| Regex scanner (JS/TS targets) | ⏳ Planned |
| CLI entry point | ⏳ Planned |
| **LLM integration** | |
| Shared LLM access layer (`llm.py`) | ✅ Done — `init_chat_model`, env-driven model selection, graceful no-key fallback |
| LLM layer: reporter | ✅ Done (executive summary) — LLM-polished prose grounded in computed facts, deterministic fallback; action-plan / per-finding narrative still planned |
| LLM layer: evaluator | ✅ Done — blind second-opinion on low-confidence findings (re-judges source code independently of the agent's score); records agent-vs-LLM divergence per risk type; deterministic fallback |
| LLM layer: prompt injection agent | ✅ Done — LLM reads the tool's full source and judges whether untrusted input really reaches a prompt, replacing the brittle param-name regex; clears false positives (allowlisted / reassigned / not-a-prompt cases) while keeping the same inputs, output shape, and pipeline position; deterministic regex fallback when no key is configured |
| LLM layer: capability analysis | ⏳ Planned — richer trust boundary descriptions; JS/TS support |
| **RAG** | |
| Schemas (`RagDocument` / `RagContext`) + graph node | ✅ Done — retrieval runs after the Evaluator, on accepted findings only |
| Knowledge base (5 docs, one per risk class) | ✅ Done — curated CWE/OWASP material; upgrade to verbatim official excerpts planned |
| Retriever (`knowledge_retriever.py`) | ✅ Done — OpenAI embeddings + Chroma, TF-IDF fallback, distance cutoff |
| Reporter: per-finding References section | ✅ Done — deterministic citations (title + source URL) |
| Retrieval quality eval (hit@k) | ⏳ Planned — fold into the existing eval harness |
| Multiple docs per class + retrieval tuning (threshold / top-k) | ⏳ Planned — makes vector search non-trivial; tune with real data |
| Feed retrieved content into reporter LLM narrative ("G" of RAG) | ⏳ Planned — together with the per-finding LLM narrative upgrade |

## Design Principles

- **Evidence-first:** every `RiskFinding` must include a file path, line range, and code snippet — findings without evidence are rejected by the Evaluator
- **Deterministic before LLM:** file scanning, AST parsing, and regex matching run as plain Python tools; the LLM handles semantic interpretation and risk explanation only
- **Structured outputs:** all agent outputs are typed Pydantic models, not free text — enables automated testing and downstream processing
- **Replayable:** the graph can regenerate a report from intermediate JSON for debugging and demos
