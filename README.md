# MCP Security Analysis Multi-Agent

A LangGraph-powered multi-agent system that analyzes MCP (Model Context Protocol) project directories for security vulnerabilities and generates evidence-backed reports.

---

## What It Does

Point it at any MCP server/client project directory, and it will:

1. **Scan the directory** — inventory all source files and filter out noise
2. **Profile the project** — understand what MCP capabilities it exposes and where the trust boundaries are
3. **Extract code features** — use static analysis (AST + regex) to find dangerous patterns like shell calls, file access, and network requests
4. **Run risk agents** — five specialized agents scan for different vulnerability classes in parallel
5. **Evaluate quality** — an Evaluator checks that every finding has real evidence; low-confidence findings get flagged or sent back for re-scan
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
- **LangChain** — LLM calls, prompt templates, structured output parsing
- **Pydantic** — typed schemas for all inter-agent data; prevents hallucinated evidence
- **Python AST module** — deterministic code feature extraction (no LLM guessing)

## Project Structure

```
mcp_security_agent/
├── schemas.py          # All data structures (GraphState, RiskFinding, etc.)
├── graph.py            # LangGraph graph: nodes, edges, conditional routing
├── cli.py              # Command-line entry point
├── agents/
│   ├── functional.py           # Capability analysis agent
│   ├── risk_prompt_injection.py
│   ├── risk_command.py
│   ├── risk_file.py
│   ├── risk_network.py
│   ├── risk_lifecycle.py
│   ├── evaluator.py
│   └── reporter.py
└── tools/
    ├── file_inventory.py   # Directory walker and file filter
    ├── ast_scanner.py      # Python AST-based feature extraction
    └── regex_scanner.py    # Pattern matching for JS/TS and config files
reports/                # Output reports land here
sample_mcp_server/      # Example target project for testing
tests/fixtures/         # Test fixtures
```

## Quickstart

```bash
# Install dependencies
pip install langgraph langchain langchain-openai pydantic

# Set your OpenAI API key
export OPENAI_API_KEY=your_key_here

# Run the skeleton (stub agents, no LLM calls needed)
python -m mcp_security_agent.graph
```

## Current Status

| Component | Status |
|---|---|
| Project structure | ✅ Done |
| Pydantic schemas | ✅ Done |
| LangGraph graph skeleton | ✅ Done — all nodes connected, full pipeline runs end-to-end |
| Directory inventory (real logic) | ✅ Done |
| Capability analysis agent | 🔧 Stub — returns placeholder data |
| Code feature extraction | 🔧 Stub — returns placeholder data |
| Risk scan agents (×5) | 🔧 Stubs |
| Evaluator agent | 🔧 Stub |
| Reporter agent | 🔧 Stub |
| CLI entry point | ⏳ Planned |

## Design Principles

- **Evidence-first:** every `RiskFinding` must include a file path, line range, and code snippet — findings without evidence are rejected by the Evaluator
- **Deterministic before LLM:** file scanning, AST parsing, and regex matching run as plain Python tools; the LLM handles semantic interpretation and risk explanation only
- **Structured outputs:** all agent outputs are typed Pydantic models, not free text — enables automated testing and downstream processing
- **Replayable:** the graph can regenerate a report from intermediate JSON for debugging and demos
