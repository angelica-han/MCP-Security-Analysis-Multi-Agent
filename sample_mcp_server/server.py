"""
Deliberately vulnerable MCP server for testing the security scanner.

This file mixes several realistic MCP tool patterns with intentionally unsafe
implementation choices. Do not copy this into a real server.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("vulnerable-sample")
BASE_DIR = Path(__file__).parent / "data"

# Legacy-style process-global state. In a stateful server, this can leak data
# across users or conversations if it is not keyed by a caller identity.
LAST_RESULT: str | None = None

# Newer stateless MCP designs often replace hidden session state with explicit
# handles. This sample makes the handles predictable and forgets authorization.
WORKSPACES: dict[str, dict[str, str]] = {}


@mcp.tool()
def run_shell(command: str) -> str:
    """Run a shell command and return its output."""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout + result.stderr


@mcp.tool()
def read_project_file(relative_path: str) -> str:
    """Read a project file by relative path."""
    target_path = BASE_DIR / relative_path
    with open(target_path, "r", encoding="utf-8") as handle:
        return handle.read()


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return the first 1000 characters."""
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers, timeout=5)
    return response.text[:1000]


@mcp.tool()
def draft_summary_prompt(notes: str) -> str:
    """Create a summarization prompt from user-provided notes."""
    return f"""
You are a careful research assistant.
Summarize the following notes.

Notes:
{notes}
"""


@mcp.tool()
def remember_last_result(result: str) -> str:
    """Store the latest result for later retrieval."""
    global LAST_RESULT
    LAST_RESULT = result
    return "saved"


@mcp.tool()
def get_last_result() -> str:
    """Return the latest stored result."""
    return LAST_RESULT or ""


@mcp.tool()
def create_workspace(owner_id: str, secret_notes: str) -> str:
    """Create a workspace and return a handle for future calls."""
    workspace_id = f"workspace-{len(WORKSPACES) + 1}"
    WORKSPACES[workspace_id] = {
        "owner_id": owner_id,
        "secret_notes": secret_notes,
    }
    return workspace_id


@mcp.tool()
def read_workspace(workspace_id: str) -> str:
    """Read workspace notes by handle."""
    workspace = WORKSPACES[workspace_id]
    return workspace["secret_notes"]


if __name__ == "__main__":
    mcp.run()

