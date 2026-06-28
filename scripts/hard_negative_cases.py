"""
hard_negative_cases.py — "looks dangerous but safe" labeled cases.

Why they exist:
- Quantify how often each agent over-reports (false-positive rate per agent),
  which tells us which agents most need an LLM second opinion.
- Give a before/after measuring stick: run the deterministic agent for a
  baseline, wire in the LLM, re-run, and show the false-positive drop.

"""

from __future__ import annotations


FAKE_MCP_HEADER = '''
class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()
'''


HARD_NEGATIVE_CASES = [
    # ── prompt_injection 1: allowlisted before reaching the prompt → safe ──

    {
        "case_id": "case_10_prompt_injection_allowlisted_safe",
        "description": "Tool param is interpolated into a prompt, but only after being "
                       "checked against a fixed allowlist — so it can't carry injection.",
        "scan_categories": ["prompt_injection"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

ALLOWED_TOPICS = {{"news", "sports", "weather"}}

@mcp.tool
def summarize_topic(topic: str) -> str:
    if topic not in ALLOWED_TOPICS:
        raise ValueError("unknown topic")
    prompt = f"Write a short summary about today's {{topic}}."
    return prompt
'''
        },
        "expected_findings": [],
        "expected_absent": ["prompt_injection"],
    },

    # ── prompt_injection 2: param overwritten with a constant → safe ──

    {
        "case_id": "case_11_prompt_injection_param_overwritten_safe",
        "description": "The user param name appears in the prompt f-string, but it was "
                       "reassigned to a fixed constant first, so user input never reaches it.",
        "scan_categories": ["prompt_injection"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def daily_greeting(user_text: str) -> str:
    user_text = "Generate a friendly good-morning message."
    prompt = f"You are a helpful assistant. {{user_text}}"
    return prompt
'''
        },
        "expected_findings": [],
        "expected_absent": ["prompt_injection"],
    },

    # ── prompt_injection 3: string is not a prompt → safe ──

    {
        "case_id": "case_12_prompt_injection_not_a_prompt_safe",
        "description": "User param is interpolated into a user-facing confirmation string "
                       "that is never sent to an LLM as instructions.",
        "scan_categories": ["prompt_injection"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def record_feedback(user_text: str) -> str:
    message = f"Thank you for your feedback: {{user_text}}"
    return message
'''
        },
        "expected_findings": [],
        "expected_absent": ["prompt_injection"],
    },

    # ── command_exec: allowlist + shell=False → safe ──

    {
        "case_id": "case_13_command_exec_allowlisted_safe",
        "description": "Tool reaches subprocess.run, but only with a hardcoded command "
                       "list selected via an allowlist; shell=False, no user string.",
        "scan_categories": ["command_exec"],
        "files": {
            "server.py": f'''
import subprocess

{FAKE_MCP_HEADER}

ALLOWED_CMDS = {{
    "status": ["systemctl", "status"],
    "uptime": ["uptime"],
}}

@mcp.tool
def run_diagnostic(name: str) -> str:
    if name not in ALLOWED_CMDS:
        raise ValueError("unknown diagnostic")
    result = subprocess.run(
        ALLOWED_CMDS[name],
        shell=False,
        capture_output=True,
        text=True,
    )
    return result.stdout
'''
        },
        "expected_findings": [],
        "expected_absent": ["command_exec"],
    },

    # ── file_access: basename + fixed base dir → safe ──

    {
        "case_id": "case_14_file_access_confined_safe",
        "description": "Tool opens a file from user input, but basename strips path "
                       "components and the path is confined to a fixed base directory.",
        "scan_categories": ["file_access"],
        "files": {
            "server.py": f'''
import os

{FAKE_MCP_HEADER}

SAFE_DIR = "/srv/reports"

@mcp.tool
def read_report(name: str) -> str:
    full_path = os.path.join(SAFE_DIR, os.path.basename(name))
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()
'''
        },
        "expected_findings": [],
        "expected_absent": ["file_access"],
    },

    # ── network_ssrf: host allowlist → safe ──

    {
        "case_id": "case_15_network_allowlisted_host_safe",
        "description": "Tool makes an outbound request with a user-provided host, but the "
                       "host must pass a strict allowlist before the request is made.",
        "scan_categories": ["network"],
        "files": {
            "server.py": f'''
import requests

{FAKE_MCP_HEADER}

ALLOWED_HOSTS = {{"api.example.com", "data.example.com"}}

@mcp.tool
def fetch_status(host: str) -> str:
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    response = requests.get(f"https://{{host}}/status", timeout=5)
    return response.text
'''
        },
        "expected_findings": [],
        "expected_absent": ["network_ssrf"],
    },

    # ── lifecycle_leak: logs length only, not content → safe ──

    {
        "case_id": "case_16_lifecycle_log_length_only_safe",
        "description": "Tool logs a line that mentions the param name, but only logs its "
                       "length — the sensitive value itself is never written to the log.",
        "scan_categories": ["lifecycle"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def search_notes(query: str) -> str:
    print(f"search_notes called, query length={{len(query)}}")
    return "ok"
'''
        },
        "expected_findings": [],
        "expected_absent": ["lifecycle_leak"],
    },
]
