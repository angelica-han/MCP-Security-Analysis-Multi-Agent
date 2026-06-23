"""
graph.py — LangGraph pipeline definition

Pipeline:
    START
      ↓
  [inventory]              Walk the project directory; list candidate files
      ↓
  [extract]                Extract code features via AST scanner
      ↓
  [profile]                Capability analysis agent (V1: rule-based, uses code_features)
      ↓
  [supervisor]             Decide which risk-scan categories to activate
      ↓
  [scan_command]           Command-execution risk scan
  [scan_prompt_injection]  Prompt-injection risk scan
  [scan_file]              File-access risk scan
  [scan_network]           Network / SSRF risk scan
  [scan_lifecycle]         Lifecycle risk scan (cleanup, log leakage, session state)
      ↓
  [evaluate]               Quality gate: accept / reject / merge / rerun
      ↓        ↘ needs_rerun → back to supervisor (max 2 times)
  [report]                 Generate final report
      ↓
    END
"""

import os
from langgraph.graph import StateGraph, END

from mcp_security_agent.agents.functional import analyze_capabilities
from mcp_security_agent.agents.reporter import generate_report
from mcp_security_agent.agents.risk_command import scan_command_risks
from mcp_security_agent.agents.risk_prompt_injection import scan_prompt_injection_risks
from mcp_security_agent.agents.risk_file import scan_file_risks
from mcp_security_agent.agents.risk_network import scan_network_risks
from mcp_security_agent.agents.risk_lifecycle import scan_lifecycle_risks
from mcp_security_agent.agents.evaluator import evaluate_findings
from mcp_security_agent.schemas import (
    GraphState,
    FileInventory,
    FileInfo,
    ProjectProfile,
    EvalResult,
    FinalReport,
)
from mcp_security_agent.tools.ast_scanner import scan_project


# ══════════════════════════════════════════════
# Node functions
# Each function receives GraphState and returns a dict of updated fields.
# LangGraph merges the returned dict back into the shared state.
# ══════════════════════════════════════════════

def node_inventory(state: GraphState) -> dict:
    """
    Node 1 — Directory inventory.
    Walks the project path, classifies files by extension, and builds a
    FileInventory. No LLM required; pure Python file-system traversal.
    """
    print("📁 [inventory] Scanning project directory...")

    project_path = state.scan_request.project_path
    config = state.scan_request.config

    candidate_files = []
    skipped = []
    lang_dist = {}

    ext_to_lang = {
        ".py": "python", ".ts": "typescript", ".js": "javascript",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        ".md": "markdown", ".toml": "toml",
    }

    for root, dirs, files in os.walk(project_path):
        # Skip directories that are unlikely to contain relevant source code
        dirs[:] = [d for d in dirs if d not in config.ignored_dirs]

        for filename in files:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, project_path)
            ext = os.path.splitext(filename)[1].lower()
            lang = ext_to_lang.get(ext)

            if lang is None:
                skipped.append(rel_path)
                continue

            size = os.path.getsize(full_path)
            is_entry = filename in ("server.py", "main.py", "index.ts", "index.js", "package.json")

            candidate_files.append(FileInfo(
                path=rel_path,
                language=lang,
                size_bytes=size,
                is_entry=is_entry,
            ))
            lang_dist[lang] = lang_dist.get(lang, 0) + 1

            if len(candidate_files) >= config.max_files:
                break

    inventory = FileInventory(
        total_files=len(candidate_files) + len(skipped),
        candidate_files=candidate_files,
        skipped_files=skipped,
        language_distribution=lang_dist,
    )

    print(f"   Found {len(candidate_files)} candidate file(s), skipped {len(skipped)}")
    return {"file_inventory": inventory}


def node_extract(state: GraphState) -> dict:
    """
    Node 2 — Code feature extraction.
    Runs the AST scanner over Python source files to detect MCP tool
    registrations and dangerous sinks (shell calls, file access, etc.).
    Must run before node_profile so that code_features are available.
    """
    print("⚙️  [extract] Extracting code features...")

    features = scan_project(
        project_path=state.scan_request.project_path,
        inventory=state.file_inventory,
    )

    print(f"   Extracted {len(features)} code feature(s)")
    return {"code_features": features}


def node_profile(state: GraphState) -> dict:
    """
    Node 3 — Capability analysis agent (V1: rule-based, no LLM).
    Runs after node_extract; infers project type and sensitive capabilities
    directly from code_features.
    TODO (V2): add an LLM layer for richer semantic analysis.
    """
    print("🔍 [profile] Analysing project capabilities...")

    profile = analyze_capabilities(
        file_inventory=state.file_inventory,
        code_features=state.code_features,
    )

    print(f"   Project type: {profile.project_type}")
    print(f"   Sensitive capabilities: {profile.sensitive_capabilities}")
    print(f"   Files flagged for deep scan: {len(profile.files_for_deep_scan)}")

    return {"project_profile": profile}


def node_supervisor(state: GraphState) -> dict:
    """
    Node 4 — Supervisor: decide which risk-scan categories to activate.

    Capability → category mapping:
        "shell_exec"          → "command_exec"
        "file_read"           → "file_access"
        "network"             → "network"
        "prompt_construction" → "prompt_injection"

    Extra rule for prompt_injection: always activate when the project exposes
    MCP tools, because any tool parameter is a potential injection entry point.

    The result is intersected with the user's ScanConfig.risk_categories so
    that explicitly disabled categories are never activated.
    """
    print("🎯 [supervisor] Deciding scan strategy...")

    _CAP_TO_CATEGORY = {
        "shell_exec":          "command_exec",
        "file_read":           "file_access",
        "network":             "network",
        "prompt_construction": "prompt_injection",
    }

    profile = state.project_profile
    if profile is None:
        # No profile available — activate all categories to avoid missing findings
        active = list(state.scan_request.config.risk_categories)
        print(f"   ⚠️  No profile found; activating all categories: {active}")
        return {"active_scan_categories": active}

    categories: set[str] = set()

    # Always scan for prompt injection when MCP tools are present
    if "tools" in profile.mcp_capabilities:
        categories.add("prompt_injection")

    # Always scan lifecycle when the project exposes MCP tools or accesses files —
    # both create state/resource management obligations
    if "tools" in profile.mcp_capabilities or "file_read" in profile.sensitive_capabilities:
        categories.add("lifecycle")

    # Add other categories based on detected sensitive capabilities
    for cap in profile.sensitive_capabilities:
        cat = _CAP_TO_CATEGORY.get(cap)
        if cat:
            categories.add(cat)

    # Intersect with user-requested categories
    requested = set(state.scan_request.config.risk_categories)
    active = sorted(categories & requested)

    print(f"   Active scan categories: {active}")
    return {"active_scan_categories": active}


def node_scan_command(state: GraphState) -> dict:
    """
    Node 5a — Command-execution risk scan.
    Skipped if the project has no shell_exec capability (supervisor did not activate it).
    V1: deterministic rules; V2 may add an LLM explanation layer.
    """
    if "command_exec" not in state.active_scan_categories:
        print("💣 [scan_command] Skipped (no shell_exec capability detected)")
        return {}
    print("💣 [scan_command] Scanning for command-execution risks...")

    findings = scan_command_risks(state.code_features)
    print(f"   Found {len(findings)} command-execution finding(s)")

    return {"risk_findings": state.risk_findings + findings}


def node_scan_prompt_injection(state: GraphState) -> dict:
    """
    Node 5b — Prompt-injection risk scan.
    Skipped if the project has no MCP tools and no prompt_construction capability.
    """
    if "prompt_injection" not in state.active_scan_categories:
        print("💉 [scan_prompt_injection] Skipped (no prompt_construction capability or MCP tools)")
        return {}
    print("💉 [scan_prompt_injection] Scanning for prompt-injection risks...")

    findings = scan_prompt_injection_risks(state.code_features)
    print(f"   Found {len(findings)} prompt-injection finding(s)")

    return {"risk_findings": state.risk_findings + findings}


def node_scan_file(state: GraphState) -> dict:
    """
    Node 5c — File-access risk scan.
    Skipped if the project has no file_read capability.
    """
    if "file_access" not in state.active_scan_categories:
        print("📂 [scan_file] Skipped (no file_read capability detected)")
        return {}
    print("📂 [scan_file] Scanning for file-access risks...")

    findings = scan_file_risks(state.code_features)
    print(f"   Found {len(findings)} file-access finding(s)")

    return {"risk_findings": state.risk_findings + findings}


def node_scan_network(state: GraphState) -> dict:
    """
    Node 5d — Network / SSRF risk scan.
    Skipped if the project has no network capability.
    """
    if "network" not in state.active_scan_categories:
        print("🌐 [scan_network] Skipped (no network capability detected)")
        return {}
    print("🌐 [scan_network] Scanning for network / SSRF risks...")

    findings = scan_network_risks(state.code_features)
    print(f"   Found {len(findings)} network finding(s)")

    return {"risk_findings": state.risk_findings + findings}


def node_scan_lifecycle(state: GraphState) -> dict:
    """
    Node 5e — Lifecycle risk scan.
    Checks for incomplete file cleanup, log leakage, and shared session state.
    Skipped if "lifecycle" is not in active_scan_categories.
    """
    if "lifecycle" not in state.active_scan_categories:
        print("♻️  [scan_lifecycle] Skipped (lifecycle category not enabled)")
        return {}
    print("♻️  [scan_lifecycle] Scanning for lifecycle risks...")

    findings = scan_lifecycle_risks(state.code_features)
    print(f"   Found {len(findings)} lifecycle finding(s)")

    return {"risk_findings": state.risk_findings + findings}


def node_evaluate(state: GraphState) -> dict:
    """
    Node 6 — Evaluator: quality gate for all risk findings.
    Accepts, rejects, or merges findings; may request a rerun for coverage gaps.
    Never modifies evidence, attack_path, or any other content field.
    """
    print("✅ [evaluate] Evaluating finding quality...")

    expected = state.scan_request.config.risk_categories if state.scan_request else None
    project_path = state.scan_request.project_path if state.scan_request else None
    eval_result = evaluate_findings(
        state.risk_findings,
        expected_categories=expected,
        project_path=project_path,
    )

    accepted_count = len(eval_result.accepted_finding_ids)
    rejected_count = len(eval_result.rejected_finding_ids)
    merged_count = len(eval_result.merged_finding_ids)
    print(f"   Accepted {accepted_count} | Rejected {rejected_count} | Merged {merged_count}")
    if eval_result.llm_rejudged_count:
        print(f"   🤖 LLM re-judged {eval_result.llm_rejudged_count} low-confidence finding(s):")
        for d in eval_result.divergence_by_type:
            print(
                f"      {d.risk_type}: {d.rejudged_count} re-judged, "
                f"{d.likely_false_positives} likely false positive(s), mean Δ {d.mean_abs_delta}"
            )
    if eval_result.needs_rerun:
        print(f"   ⚠️  Coverage gap — requesting rerun for: {eval_result.rerun_categories}")

    # Filter risk_findings down to only accepted findings
    accepted_set = set(eval_result.accepted_finding_ids)
    accepted_findings = [f for f in state.risk_findings if f.finding_id in accepted_set]

    return {
        "eval_result": eval_result,
        "risk_findings": accepted_findings,
        "rerun_count": state.rerun_count + (1 if eval_result.needs_rerun else 0),
    }


def node_report(state: GraphState) -> dict:
    """
    Node 7 — Report generation agent (V1: deterministic, no LLM).
    Assembles accepted findings into a structured Markdown report with
    severity grouping, action plan, and coverage notes.
    """
    print("📄 [report] Generating final report...")

    report = generate_report(
        findings=state.risk_findings,
        project_profile=state.project_profile,
        eval_result=state.eval_result,
        scan_request=state.scan_request,
    )

    print(f"   Overall risk level: {report.overall_risk_level.upper()}")
    print(f"   Action plan items: {len(report.action_plan)}")

    return {"final_report": report}


# ══════════════════════════════════════════════
# Conditional routing
# Determines which edge to follow after the Evaluator node.
# ══════════════════════════════════════════════

def route_after_evaluate(state: GraphState) -> str:
    """
    Route after evaluation:
    - needs_rerun and rerun_count < 2 → back to supervisor for another scan pass
    - otherwise                        → proceed to report generation
    """
    if state.eval_result and state.eval_result.needs_rerun and state.rerun_count < 2:
        print(f"🔄 [router] Quality threshold not met — rerun #{state.rerun_count + 1}...")
        return "supervisor"
    return "report"


# ══════════════════════════════════════════════
# Graph assembly
# ══════════════════════════════════════════════

def build_graph():
    """Wire all nodes and edges together and return the compiled graph."""
    graph = StateGraph(GraphState)

    # Register nodes
    graph.add_node("inventory", node_inventory)
    graph.add_node("profile", node_profile)
    graph.add_node("extract", node_extract)
    graph.add_node("supervisor", node_supervisor)
    graph.add_node("scan_command", node_scan_command)
    graph.add_node("scan_prompt_injection", node_scan_prompt_injection)
    graph.add_node("scan_file", node_scan_file)
    graph.add_node("scan_network", node_scan_network)
    graph.add_node("scan_lifecycle", node_scan_lifecycle)
    graph.add_node("evaluate", node_evaluate)
    graph.add_node("report", node_report)

    # Fixed edges: inventory → extract → profile → supervisor
    # extract runs the AST scan first so code_features are ready for profile
    graph.set_entry_point("inventory")
    graph.add_edge("inventory", "extract")
    graph.add_edge("extract", "profile")
    graph.add_edge("profile", "supervisor")

    # Supervisor → serial risk scans (results accumulate in risk_findings)
    graph.add_edge("supervisor", "scan_command")
    graph.add_edge("scan_command", "scan_prompt_injection")
    graph.add_edge("scan_prompt_injection", "scan_file")
    graph.add_edge("scan_file", "scan_network")
    graph.add_edge("scan_network", "scan_lifecycle")
    graph.add_edge("scan_lifecycle", "evaluate")

    # Conditional edge after evaluation
    graph.add_conditional_edges(
        "evaluate",
        route_after_evaluate,
        {
            "supervisor": "supervisor",  # rerun
            "report": "report",          # proceed
        }
    )

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by other modules and the CLI
app = build_graph()


# ══════════════════════════════════════════════
# Quick smoke-test entry point
# ══════════════════════════════════════════════

if __name__ == "__main__":
    from mcp_security_agent.schemas import ScanRequest, ScanConfig

    print("=" * 50)
    print("🚀 MCP Security Analysis — pipeline test")
    print("=" * 50)

    # Scan the project itself as the test target
    import os
    test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    initial_state = GraphState(
        scan_request=ScanRequest(
            project_path=test_path,
            config=ScanConfig(scan_depth="quick", max_files=20),
        )
    )

    result = app.invoke(initial_state)

    print()
    print("=" * 50)
    print("✅ Pipeline complete — final report:")
    print("=" * 50)
    if result["final_report"]:
        print(result["final_report"].report_markdown)
        os.makedirs("results", exist_ok=True)

        # Timestamped filename so every run is preserved — this keeps the full
        # iteration history (e.g. before/after adding the LLM evaluator) instead
        # of overwriting it. results/ is gitignored, so these don't clutter git.
        from datetime import datetime
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_path = f"results/report_{stamp}.md"
        with open(report_path, "w") as f:
            f.write(result["final_report"].report_markdown)

        # Also refresh a stable "latest" copy for convenience.
        with open("results/report_latest.md", "w") as f:
            f.write(result["final_report"].report_markdown)

        print(f"📄 Report saved to {report_path}  (latest: results/report_latest.md)")
