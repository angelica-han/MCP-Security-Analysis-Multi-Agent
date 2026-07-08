"""
schemas.py — Shared data contracts for the MCP Security Analysis pipeline.

All inter-agent data structures are defined here as Pydantic models.
Every agent's input and output must conform to these schemas; Pydantic
validates fields automatically and prevents agents from emitting malformed
or incomplete data.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# 1. User input
# ─────────────────────────────────────────────

class ScanConfig(BaseModel):
    """User-supplied scan configuration (all fields optional)."""
    scan_depth: Literal["quick", "standard", "deep"] = "standard"
    ignored_dirs: list[str] = Field(
        default_factory=lambda: ["node_modules", ".venv", "dist", "__pycache__", ".git"]
    )
    risk_categories: list[str] = Field(
        default_factory=lambda: ["prompt_injection", "command_exec", "file_access", "network", "lifecycle"]
    )
    max_files: int = 100
    report_format: Literal["markdown", "json", "both"] = "markdown"


class ScanRequest(BaseModel):
    """
    Pipeline entry point: user input.
    Carries the project path and scan configuration into the graph.
    """
    project_path: str                        # Local path of the MCP project to analyse
    config: ScanConfig = Field(default_factory=ScanConfig)


# ─────────────────────────────────────────────
# 2. Directory inventory
# ─────────────────────────────────────────────

class FileInfo(BaseModel):
    """Metadata for a single candidate file."""
    path: str                                # Relative path from project root
    language: Optional[str] = None          # "python" / "typescript" / "json" / etc.
    size_bytes: int = 0
    is_entry: bool = False                  # True if the file is a likely entry point


class FileInventory(BaseModel):
    """
    Output of the inventory node.
    Records which files exist in the project and their language distribution.
    """
    total_files: int
    candidate_files: list[FileInfo]         # Files selected for further analysis
    skipped_files: list[str] = Field(default_factory=list)
    language_distribution: dict[str, int] = Field(default_factory=dict)  # e.g. {"python": 5, "json": 2}


# ─────────────────────────────────────────────
# 3. Capability analysis result
# ─────────────────────────────────────────────

class ProjectProfile(BaseModel):
    """
    Output of the capability analysis agent (functional.py).
    Answers "what does this MCP project do?" in a structured way.
    """
    project_type: Literal["mcp_server", "mcp_client", "mixed", "unknown"]
    entry_points: list[str]                 # Files that are likely entry points
    mcp_capabilities: list[str]            # MCP primitives in use: tools / resources / prompts
    sensitive_capabilities: list[str]      # Dangerous capabilities: file_read / shell_exec / network / etc.
    trust_boundary: str                    # Description of where untrusted input can reach dangerous sinks
    files_for_deep_scan: list[dict]        # Files prioritised for deep scanning, with reasons
    summary: str                           # Natural-language summary of the project


# ─────────────────────────────────────────────
# 4. Code feature extraction
# ─────────────────────────────────────────────

class CodeSource(BaseModel):
    """Location and snippet of a code feature within a source file."""
    file_path: str
    line_start: int
    line_end: int
    snippet: str                            # Actual source code


class CodeFeature(BaseModel):
    """
    Output of the AST scanner.
    Each CodeFeature represents one signal: a piece of code that may be
    security-relevant (an MCP tool registration, a dangerous sink, etc.).
    """
    feature_id: str                         # Unique ID for tracing
    feature_type: Literal[
        "mcp_tool",
        "file_access",
        "network_request",
        "command_execution",
        "prompt_construction"
    ]
    source: CodeSource                      # Where the feature was found
    user_controlled_inputs: list[str]       # Parameter names that are user-controlled
    sink: str                               # Final destination, e.g. "subprocess.run"
    notes: str                              # Why this feature matters for MCP security


# ─────────────────────────────────────────────
# 5. Risk findings (output of each risk agent)
# ─────────────────────────────────────────────

class RiskFinding(BaseModel):
    """
    Output of the risk-scan agents (risk_command, risk_file, etc.).
    Every finding must include concrete evidence — findings without
    evidence are rejected by the Evaluator.
    """
    finding_id: str
    risk_type: Literal[
        "prompt_injection",
        "command_exec",
        "file_access",
        "network_ssrf",
        "lifecycle_leak"
    ]
    severity: Literal["critical", "high", "medium", "low"]
    confidence: float = Field(ge=0.0, le=1.0)   # Effective score; below 0.55 triggers rejection.
                                                # After LLM re-judgment this holds the LLM's score.
    file_path: str
    line_range: tuple[int, int]
    evidence: str                               # Verbatim code snippet — must be real
    attack_path: str                            # Input → dangerous operation chain
    impact: str                                 # Consequence if exploited
    remediation: str                            # Concrete fix recommendation
    false_positive_notes: str = ""
    source_feature_id: Optional[str] = None    # ID of the CodeFeature that triggered this finding

    # ── LLM second-opinion fields ──
    # Set only when the LLM evaluator re-judges a low-confidence finding.
    # The LLM judges the source code BLIND — it never sees the agent's score or
    # reasoning — so agent_confidence vs llm_confidence is a meaningful divergence.
    agent_confidence: Optional[float] = None   # original hard-coded score, preserved for analysis
    llm_confidence: Optional[float] = None      # independent blind re-judgment (None = not re-judged)
    llm_rationale: str = ""                      # one-line reason from the LLM


# ─────────────────────────────────────────────
# 6. Evaluator quality-gate result
# ─────────────────────────────────────────────

class AgentDivergence(BaseModel):
    """
    Per-risk_type comparison of agent confidence vs the LLM's blind re-judgment,
    over the findings the LLM evaluator actually re-scored.

    A large divergence means the agent's hard-coded scoring disagrees with an
    independent LLM read of the same code — a signal that this agent (e.g.
    prompt_injection, which only keyword-matches) is a candidate for its own
    LLM upgrade. Consumed later by the reporter to suggest agent improvements.
    """
    risk_type: str
    rejudged_count: int = 0           # findings of this type the LLM re-scored
    over_0_2: int = 0                 # |agent_conf - llm_conf| > 0.2
    over_0_3: int = 0                 # |agent_conf - llm_conf| > 0.3
    likely_false_positives: int = 0   # agent scored it plausible but LLM scored it low
    mean_abs_delta: float = 0.0       # average |agent_conf - llm_conf|


class EvalResult(BaseModel):
    """
    Output of the Evaluator agent.
    Records which findings were accepted, rejected, or merged, and whether
    any scan categories need to be re-run to fill coverage gaps.

    The Evaluator is only permitted to manipulate ID lists — it must never
    rewrite evidence, attack_path, or any other content field.

    accepted:    True if at least one finding passed the quality gate
    pipeline_ok: True if the evaluation process itself completed successfully
                 (includes the legitimate case where a clean scan finds nothing)
    """
    accepted: bool
    pipeline_ok: bool = True
    overall_confidence: float = Field(ge=0.0, le=1.0)
    missing_categories: list[str] = Field(default_factory=list)
    needs_rerun: bool = False
    rerun_categories: list[str] = Field(default_factory=list)
    # ID lists only — content is never rewritten
    accepted_finding_ids: list[str] = Field(default_factory=list)
    rejected_finding_ids: list[str] = Field(default_factory=list)
    merged_finding_ids: list[str] = Field(default_factory=list)   # IDs folded into a surviving finding
    risk_summary: dict[str, int] = Field(default_factory=dict)   # e.g. {"critical": 1, "high": 2}
    evaluator_notes: str = ""

    # ── LLM second-opinion summary ──
    llm_rejudged_count: int = 0                                   # total findings re-scored by the LLM
    divergence_by_type: list[AgentDivergence] = Field(default_factory=list)


# ─────────────────────────────────────────────
# 6.5 RAG knowledge-base context
#     Produced by the retrieval node (after the Evaluator, for accepted
#     findings only); consumed by the Reporter to ground remediation
#     advice in authoritative references (CWE / OWASP / MCP docs).
# ─────────────────────────────────────────────

class RagDocument(BaseModel):
    """One retrieved knowledge-base document used to enrich a finding."""
    doc_id: str
    title: str
    source: str = ""                        # URL of the authoritative origin
    risk_type: str = ""                     # matches RiskFinding.risk_type values
    content: str
    distance: Optional[float] = None        # retrieval distance; lower = more similar


class RagContext(BaseModel):
    """Retrieved RAG context for one accepted finding."""
    finding_id: str
    query: str                              # the query string built from the finding
    documents: list[RagDocument] = Field(default_factory=list)


# ─────────────────────────────────────────────
# 7. Final report
# ─────────────────────────────────────────────

class FinalReport(BaseModel):
    """Pipeline output: the final security report."""
    project_path: str
    overall_risk_level: Literal["critical", "high", "medium", "low", "safe"]
    executive_summary: str
    accepted_findings: list[RiskFinding]
    coverage_notes: str
    action_plan: list[str]
    report_markdown: str = ""


# ─────────────────────────────────────────────
# 8. GraphState — LangGraph shared state
#    Passed through the entire pipeline; each node reads from it
#    and writes its output back into it.
# ─────────────────────────────────────────────

class GraphState(BaseModel):
    """
    Shared state object ("work order") for the LangGraph pipeline.
    Each node fills in its output field(s) and leaves the rest unchanged.
    None indicates a stage that has not yet executed.
    """
    # Input
    scan_request: Optional[ScanRequest] = None

    # Stage outputs (in pipeline order)
    file_inventory: Optional[FileInventory] = None
    project_profile: Optional[ProjectProfile] = None
    code_features: list[CodeFeature] = Field(default_factory=list)
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    eval_result: Optional[EvalResult] = None
    rag_contexts: list[RagContext] = Field(default_factory=list)
    final_report: Optional[FinalReport] = None

    # Flow-control fields
    rerun_count: int = 0                    # How many rerun loops have been executed (cap: 2)
    active_scan_categories: list[str] = Field(
        # Supervisor overwrites this based on ProjectProfile.
        # Default is all-on so the pipeline works even if profile is missing.
        default_factory=lambda: ["prompt_injection", "command_exec", "file_access", "network"]
    )
    error_message: Optional[str] = None
