"""
graph.py — LangGraph 图骨架

这里定义了整个分析流水线的结构：节点、边、条件路由。
现在除了第一个节点都是"占位函数"（返回假数据），
之后我们会一个一个替换成真正的 Agent。

流程图：
    START
      ↓
  [inventory]     读取目录，列出文件
      ↓
  [profile]       分析项目功能（占位：假数据）
      ↓
  [extract]       提取代码特征（占位：假数据）
      ↓
  [supervisor]    决定跑哪些风险扫描
      ↓
  [scan_*]        各风险扫描 Agent（占位：假数据）
      ↓
  [evaluate]      Evaluator 检查质量
      ↓        ↘ needs_rerun → 回到 supervisor（最多2次）
  [report]        生成最终报告
      ↓
    END
"""

import os
from langgraph.graph import StateGraph, END

from mcp_security_agent.agents.risk_command import scan_command_risks
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
# 节点函数（LangGraph调度员）
# 每个函数接收 GraphState，返回更新后的字段（字典）
# LangGraph 会把返回的字典合并回 State
# ══════════════════════════════════════════════

def node_inventory(state: GraphState) -> dict:
    """
    节点1：读取目录，列出所有候选文件
    这是唯一一个现在就用真实逻辑的节点（纯 Python，不需要 LLM）
    """
    print("📁 [inventory] 正在读取目录...")

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
        # 过滤掉不需要扫描的目录
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

    print(f"   发现 {len(candidate_files)} 个候选文件，跳过 {len(skipped)} 个")
    return {"file_inventory": inventory}


def node_profile(state: GraphState) -> dict:
    """
    节点2：能力分析 Agent（占位）
    TODO: 替换成真正的 LLM Agent，分析项目功能和信任边界
    """
    print("🔍 [profile] 分析项目能力（占位）...")

    # 占位数据：假装分析完了
    profile = ProjectProfile(
        project_type="mcp_server",
        entry_points=["server.py"],
        mcp_capabilities=["tools", "resources"],
        sensitive_capabilities=["file_read", "shell_exec"],
        trust_boundary="用户输入的参数直接传入工具函数，未经验证",
        files_for_deep_scan=[{"path": "server.py", "reason": "入口文件，注册了 MCP tools"}],
        summary="这是一个 MCP Server 示例项目（占位分析）",
    )

    return {"project_profile": profile}


def node_extract(state: GraphState) -> dict:
    """
    节点3：代码特征提取
    使用 AST 扫描器从真实 Python 代码里提取 MCP tools 和危险 sink。
    """
    print("⚙️  [extract] 提取代码特征...")

    features = scan_project(
        project_path=state.scan_request.project_path,
        inventory=state.file_inventory,
    )

    print(f"   提取到 {len(features)} 个代码特征")
    return {"code_features": features}


def node_supervisor(state: GraphState) -> dict:
    """
    节点4：Supervisor，决定要跑哪些风险扫描 Agent
    现在直接返回空，路由逻辑在 edge 里控制
    """
    print("🎯 [supervisor] 决定扫描策略...")
    # Supervisor 本身不修改 state，只是一个路由决策点
    return {}


def node_scan_command(state: GraphState) -> dict:
    """
    节点5a：命令执行风险扫描
    第一版使用确定性规则，之后可加 LLM 解释层。
    """
    print("💣 [scan_command] 扫描命令执行风险...")

    findings = scan_command_risks(state.code_features)
    print(f"   发现 {len(findings)} 条命令执行风险")

    return {"risk_findings": state.risk_findings + findings}


def node_scan_prompt_injection(state: GraphState) -> dict:
    """节点5b：Prompt Injection 风险扫描（占位）"""
    print("💉 [scan_prompt_injection] 扫描 Prompt 注入风险（占位，暂时跳过）...")
    return {}


def node_evaluate(state: GraphState) -> dict:
    """
    节点6：Evaluator，检查风险发现的质量（占位）
    TODO: 替换成真正的评估 Agent
    """
    print("✅ [evaluate] 评估风险发现质量（占位）...")

    findings = state.risk_findings
    accepted = all(f.confidence >= 0.55 and f.evidence for f in findings)

    risk_summary = {}
    for f in findings:
        risk_summary[f.severity] = risk_summary.get(f.severity, 0) + 1

    eval_result = EvalResult(
        accepted=accepted,
        overall_confidence=sum(f.confidence for f in findings) / len(findings) if findings else 0.0,
        needs_rerun=False,
        risk_summary=risk_summary,
        evaluator_notes="占位评估：所有发现均通过基础检查",
    )

    return {"eval_result": eval_result}


def node_report(state: GraphState) -> dict:
    """
    节点7：生成最终报告（占位）
    TODO: 替换成真正的 Reporter Agent
    """
    print("📄 [report] 生成最终报告（占位）...")

    findings = state.risk_findings
    risk_summary = state.eval_result.risk_summary if state.eval_result else {}

    overall_level = "safe"
    if risk_summary.get("critical", 0) > 0:
        overall_level = "critical"
    elif risk_summary.get("high", 0) > 0:
        overall_level = "high"
    elif risk_summary.get("medium", 0) > 0:
        overall_level = "medium"
    elif risk_summary.get("low", 0) > 0:
        overall_level = "low"

    # 生成简单的 Markdown 报告
    md_lines = [
        f"# MCP 安全分析报告",
        f"",
        f"**项目路径：** `{state.scan_request.project_path}`",
        f"**整体风险等级：** {overall_level.upper()}",
        f"",
        f"## 执行摘要",
        f"共发现 {len(findings)} 条风险（占位报告）。",
        f"",
        f"## 风险详情",
    ]
    for f in findings:
        md_lines += [
            f"### [{f.severity.upper()}] {f.risk_type}",
            f"- **文件：** `{f.file_path}` 第 {f.line_range[0]}~{f.line_range[1]} 行",
            f"- **证据：** `{f.evidence}`",
            f"- **攻击路径：** {f.attack_path}",
            f"- **修复建议：** {f.remediation}",
            f"",
        ]

    report = FinalReport(
        project_path=state.scan_request.project_path,
        overall_risk_level=overall_level,
        executive_summary=f"发现 {len(findings)} 条风险，最高等级 {overall_level}。",
        accepted_findings=findings,
        coverage_notes="占位扫描：仅运行了命令执行风险扫描。",
        action_plan=[f"[P0] 修复 {f.file_path} 中的 {f.risk_type} 问题" for f in findings if f.severity in ("critical", "high")],
        report_markdown="\n".join(md_lines),
    )

    return {"final_report": report}


# ══════════════════════════════════════════════
# 条件路由函数
# 决定 Evaluator 之后走哪条边
# ══════════════════════════════════════════════

def route_after_evaluate(state: GraphState) -> str:
    """
    Evaluator 之后的路由逻辑：
    - 如果需要重跑 且 还没超过2次 → 回到 supervisor
    - 否则 → 去生成报告
    """
    if state.eval_result and state.eval_result.needs_rerun and state.rerun_count < 2:
        print(f"🔄 [router] 质量不达标，第 {state.rerun_count + 1} 次重跑...")
        return "supervisor"
    return "report"


# ══════════════════════════════════════════════
# 建图
# ══════════════════════════════════════════════

def build_graph():
    """
    把所有节点和边连起来，返回编译好的图
    """
    graph = StateGraph(GraphState)

    # 添加节点
    graph.add_node("inventory", node_inventory)
    graph.add_node("profile", node_profile)
    graph.add_node("extract", node_extract)
    graph.add_node("supervisor", node_supervisor)
    graph.add_node("scan_command", node_scan_command)
    graph.add_node("scan_prompt_injection", node_scan_prompt_injection)
    graph.add_node("evaluate", node_evaluate)
    graph.add_node("report", node_report)

    # 固定边（按照顺序执行，一个agent结束后叫下一个）
    graph.set_entry_point("inventory")
    graph.add_edge("inventory", "profile")
    graph.add_edge("profile", "extract")
    graph.add_edge("extract", "supervisor")

    # Supervisor → 并行风险扫描（现在串行，之后可以改成并行）
    graph.add_edge("supervisor", "scan_command")
    graph.add_edge("supervisor", "scan_prompt_injection")
    graph.add_edge("scan_command", "evaluate")
    graph.add_edge("scan_prompt_injection", "evaluate")

    # Evaluator 之后：条件路由
    graph.add_conditional_edges(
        "evaluate",
        route_after_evaluate,
        {
            "supervisor": "supervisor",  # 重跑
            "report": "report",          # 继续
        }
    )

    graph.add_edge("report", END)

    return graph.compile()


# 编译好的图，供外部调用
app = build_graph()


# ══════════════════════════════════════════════
# 快速测试入口
# ══════════════════════════════════════════════

if __name__ == "__main__":
    from mcp_security_agent.schemas import ScanRequest, ScanConfig

    print("=" * 50)
    print("🚀 MCP Security Analysis — 骨架测试")
    print("=" * 50)

    # 用当前目录作为测试目标
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
    print("✅ 流程跑通！最终报告：")
    print("=" * 50)
    if result["final_report"]:
        print(result["final_report"].report_markdown)
