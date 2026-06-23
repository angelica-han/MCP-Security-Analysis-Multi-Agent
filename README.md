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
6. **Generate a report** — structured Markdown + JSON output with evidence chains, attack paths, and remediation suggestions

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
- **LangChain LLM layer** — a pluggable chat model via `init_chat_model` (OpenAI / Anthropic / Google, switchable from `.env`). Currently polishes the report's **executive summary** into natural-language prose, grounded strictly in pre-computed facts, with a deterministic fallback when no key is configured. Risk scanning itself stays fully deterministic (AST + regex).

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
    ├── file_inventory.py   # Directory walker and file filter
    ├── ast_scanner.py      # Python AST-based feature extraction
    └── regex_scanner.py    # Pattern matching for JS/TS and config files
results/                # Output reports land here (gitignored)
sample_mcp_server/      # Deliberately vulnerable MCP server used as scan target
tests/fixtures/         # Test fixtures
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
| Regex scanner (JS/TS targets) | ⏳ Planned |
| CLI entry point | ⏳ Planned |
| **LLM integration** | |
| Shared LLM access layer (`llm.py`) | ✅ Done — `init_chat_model`, env-driven model selection, graceful no-key fallback |
| LLM layer: reporter | ✅ Done (executive summary) — LLM-polished prose grounded in computed facts, deterministic fallback; action-plan / per-finding narrative still planned |
| LLM layer: evaluator | ✅ Done — blind second-opinion on low-confidence findings (re-judges source code independently of the agent's score); records agent-vs-LLM divergence per risk type; deterministic fallback |
| LLM layer: prompt injection agent | ⏳ Planned — semantic taint analysis to replace string matching |
| LLM layer: capability analysis | ⏳ Planned — richer trust boundary descriptions; JS/TS support |

## Design Principles

- **Evidence-first:** every `RiskFinding` must include a file path, line range, and code snippet — findings without evidence are rejected by the Evaluator
- **Deterministic before LLM:** file scanning, AST parsing, and regex matching run as plain Python tools; the LLM handles semantic interpretation and risk explanation only
- **Structured outputs:** all agent outputs are typed Pydantic models, not free text — enables automated testing and downstream processing
- **Replayable:** the graph can regenerate a report from intermediate JSON for debugging and demos
