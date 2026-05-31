"""
AST-based feature extraction for Python MCP projects.

This module intentionally stays deterministic: it scans Python syntax trees and
emits CodeFeature objects that downstream risk agents can evaluate. The LLM can
explain a finding later, but the evidence starts here.
"""

from __future__ import annotations

import ast
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from mcp_security_agent.schemas import CodeFeature, CodeSource, FileInventory


COMMAND_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "eval",
    "exec",
}

FILE_SINKS = {
    "open",
    "Path.open",
}

NETWORK_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "httpx.get",
    "httpx.post",
}


@dataclass
class FunctionContext:
    name: str
    args: list[str]
    is_mcp_tool: bool


def scan_project(project_path: str, inventory: FileInventory | None = None) -> list[CodeFeature]:
    """Scan Python candidate files in a project and return static CodeFeatures."""
    root = Path(project_path)
    python_files = _candidate_python_files(root, inventory)

    features: list[CodeFeature] = []
    for path in python_files:
        features.extend(scan_python_file(root, path))

    return features


def scan_python_file(project_root: Path, file_path: Path) -> list[CodeFeature]:
    """Scan one Python file for MCP tools and dangerous sinks."""
    try:
        source_text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        source_text = file_path.read_text(encoding="utf-8", errors="replace")

    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return []

    lines = source_text.splitlines()
    rel_path = os.path.relpath(file_path, project_root)
    visitor = FeatureVisitor(rel_path=rel_path, lines=lines)
    visitor.visit(tree)
    return visitor.features


class FeatureVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, lines: list[str]):
        self.rel_path = rel_path
        self.lines = lines
        self.features: list[CodeFeature] = []
        self.function_stack: list[FunctionContext] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink = _call_name(node.func)
        if sink in COMMAND_SINKS:
            self.features.append(self._feature(node, "command_execution", sink, self._command_notes(node, sink)))
        elif sink in FILE_SINKS:
            self.features.append(self._feature(node, "file_access", sink, "Reads or opens a file path that may be influenced by tool arguments."))
        elif sink in NETWORK_SINKS:
            self.features.append(self._feature(node, "network_request", sink, "Performs an outbound network request from the MCP server environment."))

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        text = _safe_unparse(node)
        if _looks_like_prompt(text):
            self.features.append(self._feature(node, "prompt_construction", "f-string prompt", "Builds a prompt-like string with interpolated content."))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and _looks_like_prompt(node.value):
            self.features.append(self._feature(node, "prompt_construction", "string prompt", "Contains prompt-like instruction text."))

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = [arg.arg for arg in node.args.args]
        is_mcp_tool = any(_decorator_name(d) in {"mcp.tool", "tool"} for d in node.decorator_list)
        context = FunctionContext(name=node.name, args=args, is_mcp_tool=is_mcp_tool)

        if is_mcp_tool:
            self.features.append(self._feature(
                node,
                "mcp_tool",
                f"{node.name}",
                "Function is exposed as an MCP tool; its parameters should be treated as model/user-controlled inputs.",
                user_inputs=args,
            ))

        self.function_stack.append(context)
        self.generic_visit(node)
        self.function_stack.pop()

    def _feature(
        self,
        node: ast.AST,
        feature_type: str,
        sink: str,
        notes: str,
        user_inputs: list[str] | None = None,
    ) -> CodeFeature:
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start)
        context = self.function_stack[-1] if self.function_stack else None
        inferred_inputs = user_inputs if user_inputs is not None else (context.args if context and context.is_mcp_tool else [])

        return CodeFeature(
            feature_id=str(uuid.uuid4())[:8],
            feature_type=feature_type,  # type: ignore[arg-type]
            source=CodeSource(
                file_path=self.rel_path,
                line_start=line_start,
                line_end=line_end,
                snippet=_snippet(self.lines, line_start, line_end),
            ),
            user_controlled_inputs=inferred_inputs,
            sink=sink,
            notes=notes,
        )

    @staticmethod
    def _command_notes(node: ast.Call, sink: str) -> str:
        if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
            return f"{sink} is called with shell=True, which can execute shell metacharacters from user-controlled input."
        return f"{sink} executes dynamic code or operating-system commands."


def _candidate_python_files(project_root: Path, inventory: FileInventory | None) -> list[Path]:
    if inventory is not None:
        return [
            project_root / file_info.path
            for file_info in inventory.candidate_files
            if file_info.language == "python"
        ]

    ignored_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist"}
    paths: list[Path] = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for filename in files:
            if filename.endswith(".py"):
                paths.append(Path(root) / filename)
    return paths


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _call_name(decorator.func)
    return _call_name(decorator)


def _snippet(lines: list[str], line_start: int, line_end: int) -> str:
    selected = lines[max(line_start - 1, 0):line_end]
    return "\n".join(selected).strip()


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _looks_like_prompt(text: str) -> bool:
    lowered = text.lower()
    prompt_markers = ["you are", "summarize", "ignore previous", "system prompt", "instructions"]
    return any(marker in lowered for marker in prompt_markers)
