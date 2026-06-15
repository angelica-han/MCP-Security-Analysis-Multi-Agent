"""
schemas.py — 整个项目的"数据合同"

这里定义了流水线上传递的所有数据结构。
每个 Agent 的输入输出都必须符合这里定义的格式，
Pydantic 会自动检查，防止 Agent 输出残缺或乱写的数据。
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# 1. 用户输入
# ─────────────────────────────────────────────

class ScanConfig(BaseModel):
    """用户的扫描配置（可选项）"""
    scan_depth: Literal["quick", "standard", "deep"] = "standard"
    ignored_dirs: list[str] = Field(
        default_factory=lambda: ["node_modules", ".venv", "dist", "__pycache__", ".git"]
    )
    risk_categories: list[str] = Field(
        # "lifecycle" omitted until risk_lifecycle.py agent is built
        default_factory=lambda: ["prompt_injection", "command_exec", "file_access", "network"]
    )
    max_files: int = 100
    report_format: Literal["markdown", "json", "both"] = "markdown"


class ScanRequest(BaseModel):
    """
    流水线第一站：用户输入
    记录要扫描的项目路径和配置
    """
    project_path: str                        # 被分析的 MCP 项目的本地路径
    config: ScanConfig = Field(default_factory=ScanConfig)


# ─────────────────────────────────────────────
# 2. 目录读取结果
# ─────────────────────────────────────────────

class FileInfo(BaseModel):
    """单个文件的基本信息"""
    path: str                                # 相对路径
    language: Optional[str] = None          # "python" / "typescript" / "json" 等
    size_bytes: int = 0
    is_entry: bool = False                  # 是否疑似入口文件


class FileInventory(BaseModel):
    """
    流水线第二站：目录扫描结果
    记录项目里有哪些文件、语言分布等
    """
    total_files: int
    candidate_files: list[FileInfo]         # 筛选后值得深入分析的文件
    skipped_files: list[str] = Field(default_factory=list)
    language_distribution: dict[str, int] = Field(default_factory=dict)  # {"python": 5, "json": 2}


# ─────────────────────────────────────────────
# 3. 项目能力分析结果
# ─────────────────────────────────────────────

class ProjectProfile(BaseModel):
    """
    流水线第三站：能力分析 Agent 的输出
    搞清楚"这个 MCP 项目是干嘛的"
    """
    project_type: Literal["mcp_server", "mcp_client", "mixed", "unknown"]
    entry_points: list[str]                 # 入口文件列表
    mcp_capabilities: list[str]            # 用到了哪些 MCP 能力：tools / resources / prompts
    sensitive_capabilities: list[str]      # 危险能力：file_read / shell_exec / network 等
    trust_boundary: str                    # 信任边界描述
    files_for_deep_scan: list[dict]        # 需要深入扫描的文件，附带原因
    summary: str                           # 项目功能的自然语言总结


# ─────────────────────────────────────────────
# 4. 代码特征提取结果
# ─────────────────────────────────────────────

class CodeSource(BaseModel):
    """代码片段的位置信息"""
    file_path: str
    line_start: int
    line_end: int
    snippet: str                            # 实际代码内容


class CodeFeature(BaseModel):
    """
    流水线第四站：静态扫描工具提取的代码特征
    每一条都是一个"信号"，说明某段代码可能值得关注
    """
    feature_id: str                         # 唯一 ID，方便追踪
    feature_type: Literal[
        "mcp_tool",
        "file_access",
        "network_request",
        "command_execution",
        "prompt_construction"
    ]
    source: CodeSource                      # 在哪里发现的
    user_controlled_inputs: list[str]       # 哪些参数是用户可控的
    sink: str                               # 最终流向哪里，e.g. "subprocess.run"
    notes: str                              # 为什么这个特征对 MCP 安全有意义


# ─────────────────────────────────────────────
# 5. 风险发现（各风险 Agent 的输出）
# ─────────────────────────────────────────────

class RiskFinding(BaseModel):
    """
    流水线第五站：风险扫描 Agent 的输出
    每条风险发现都必须有完整的证据，缺一不可
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
    confidence: float = Field(ge=0.0, le=1.0)   # 置信度 0~1，低于 0.55 会被 Evaluator 标记
    file_path: str
    line_range: tuple[int, int]
    evidence: str                               # 具体代码证据，必须真实存在
    attack_path: str                            # 攻击路径：输入 → 危险操作
    impact: str                                 # 影响描述
    remediation: str                            # 修复建议
    false_positive_notes: str = ""
    source_feature_id: Optional[str] = None    # 来自哪条 CodeFeature


# ─────────────────────────────────────────────
# 6. Evaluator 质量评估结果
# ─────────────────────────────────────────────

class EvalResult(BaseModel):
    """
    流水线第六站：Evaluator Agent 的输出
    决定风险发现够不够好，要不要打回重做。

    规则：Evaluator 只能 accept / reject / merge / request_rerun。
    禁止修改 evidence、attack_path 等字段（防止 LLM 捏造证据）。

    accepted:    至少有一条 finding 通过了质检（有实质发现）
    pipeline_ok: 质检流程本身成功完成（包括"扫完但没发现问题"这种合法情况）
    """
    accepted: bool       # True = 有 findings 被接受
    pipeline_ok: bool = True  # True = 质检流程正常完成（无论有没有发现）
    overall_confidence: float = Field(ge=0.0, le=1.0)
    missing_categories: list[str] = Field(default_factory=list)
    needs_rerun: bool = False
    rerun_categories: list[str] = Field(default_factory=list)
    # ID lists only — never rewritten content
    accepted_finding_ids: list[str] = Field(default_factory=list)
    rejected_finding_ids: list[str] = Field(default_factory=list)
    merged_finding_ids: list[str] = Field(default_factory=list)   # IDs deduplicated into one
    risk_summary: dict[str, int] = Field(default_factory=dict)   # {"critical": 1, "high": 2}
    evaluator_notes: str = ""


# ─────────────────────────────────────────────
# 7. 最终报告
# ─────────────────────────────────────────────

class FinalReport(BaseModel):
    """流水线终点：最终输出的报告"""
    project_path: str
    overall_risk_level: Literal["critical", "high", "medium", "low", "safe"]
    executive_summary: str
    accepted_findings: list[RiskFinding]
    coverage_notes: str
    action_plan: list[str]
    report_markdown: str = ""


# ─────────────────────────────────────────────
# 8. GraphState — LangGraph 的"工单"
#    这是在整个流水线上传递的总状态
#    每个节点读它、往里写，传给下一个节点
# ─────────────────────────────────────────────

class GraphState(BaseModel):
    """
    LangGraph 的全局状态（工单）
    每个节点执行完后，把自己的结果填进对应字段
    None 表示这个阶段还没执行
    """
    # 输入
    scan_request: Optional[ScanRequest] = None

    # 各阶段产出（按流水线顺序）
    file_inventory: Optional[FileInventory] = None
    project_profile: Optional[ProjectProfile] = None
    code_features: list[CodeFeature] = Field(default_factory=list)
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    eval_result: Optional[EvalResult] = None
    final_report: Optional[FinalReport] = None

    # 流程控制
    rerun_count: int = 0                    # 已经重跑了几次（防止无限循环）
    error_message: Optional[str] = None
