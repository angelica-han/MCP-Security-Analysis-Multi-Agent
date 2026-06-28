from __future__ import annotations

import json
import shutil
from pathlib import Path
from textwrap import dedent

# --- Extension: hard-negative ("looks dangerous but safe") cases. ---

from hard_negative_cases import HARD_NEGATIVE_CASES


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "labeled_cases"
LABEL_PATH = ROOT / "tests" / "fixtures" / "labels.jsonl"


FAKE_MCP_HEADER = '''
class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()
'''


CASES = [
    {
        "case_id": "case_01_command_injection_shell_true",
        "description": "MCP tool passes user-controlled command into subprocess.run with shell=True.",
        "scan_categories": ["command_exec"],
        "files": {
            "server.py": f'''
import subprocess

{FAKE_MCP_HEADER}

@mcp.tool
def run_shell(command: str) -> str:
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
'''
        },
        "expected_findings": [
            {
                "risk_type": "command_exec",
                "severity": "high",
                "file_path": "server.py",
                "evidence_contains": ["subprocess.run", "shell=True"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_02_eval_user_expression",
        "description": "MCP tool evaluates user-controlled expression with eval.",
        "scan_categories": ["command_exec"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def calculate(expression: str):
    return eval(expression)
'''
        },
        "expected_findings": [
            {
                "risk_type": "command_exec",
                "severity": "critical",
                "file_path": "server.py",
                "evidence_contains": ["eval", "expression"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_03_arbitrary_file_read",
        "description": "MCP tool reads a user-controlled path without allowlist or base-dir validation.",
        "scan_categories": ["file_access"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
'''
        },
        "expected_findings": [
            {
                "risk_type": "file_access",
                "severity": "medium",
                "file_path": "server.py",
                "evidence_contains": ["open", "path"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_04_arbitrary_file_write",
        "description": "MCP tool writes user-provided content to a user-controlled path.",
        "scan_categories": ["file_access"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def save_note(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return "saved"
'''
        },
        "expected_findings": [
            {
                "risk_type": "file_access",
                "severity": "high",
                "file_path": "server.py",
                "evidence_contains": ["open", "path", '"w"'],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_05_user_controlled_url_ssrf",
        "description": "MCP tool sends a request to a user-controlled URL.",
        "scan_categories": ["network"],
        "files": {
            "server.py": f'''
import requests

{FAKE_MCP_HEADER}

@mcp.tool
def fetch_url(url: str) -> str:
    response = requests.get(url, timeout=5)
    return response.text
'''
        },
        "expected_findings": [
            {
                "risk_type": "network_ssrf",
                "severity": "high",
                "file_path": "server.py",
                "evidence_contains": ["requests.get", "url"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_06_cloud_metadata_ssrf",
        "description": "MCP tool constructs a cloud metadata URL using user-controlled input.",
        "scan_categories": ["network"],
        "files": {
            "server.py": f'''
import requests

{FAKE_MCP_HEADER}

@mcp.tool
def fetch_metadata(path: str) -> str:
    response = requests.get(
        f"http://169.254.169.254/latest/meta-data/{{path}}",
        timeout=2,
    )
    return response.text
'''
        },
        "expected_findings": [
            {
                "risk_type": "network_ssrf",
                "severity": "critical",
                "file_path": "server.py",
                "evidence_contains": ["requests.get", "169.254.169.254", "path"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_07_prompt_injection",
        "description": "MCP tool interpolates untrusted user text into a prompt-like instruction string.",
        "scan_categories": ["prompt_injection"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def summarize_text(user_text: str) -> str:
    prompt = f"You are a helpful assistant. Summarize this user content: {{user_text}}"
    return prompt
'''
        },
        "expected_findings": [
            {
                "risk_type": "prompt_injection",
                "severity": "high",
                "file_path": "server.py",
                "evidence_contains": ["You are", "Summarize", "user_text"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_08_log_leakage",
        "description": "MCP tool logs a raw user-controlled parameter.",
        "scan_categories": ["lifecycle"],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def search_private_notes(query: str) -> str:
    print(f"received query: {{query}}")
    return "ok"
'''
        },
        "expected_findings": [
            {
                "risk_type": "lifecycle_leak",
                "severity": "medium",
                "file_path": "server.py",
                "evidence_contains": ["print", "query"],
            }
        ],
        "expected_absent": [],
    },
    {
        "case_id": "case_09_safe_simple_tool",
        "description": "Safe MCP tool with no file, command, network, prompt, or lifecycle risk.",
        "scan_categories": [],
        "files": {
            "server.py": f'''
{FAKE_MCP_HEADER}

@mcp.tool
def add_numbers(a: int, b: int) -> int:
    return a + b
'''
        },
        "expected_findings": [],
        "expected_absent": [
            "command_exec",
            "file_access",
            "network_ssrf",
            "prompt_injection",
            "lifecycle_leak",
        ],
    },
]


def clean_text(text: str) -> str:
    return dedent(text).strip() + "\n"


def generate_fixtures() -> None:
    if FIXTURE_ROOT.exists():
        shutil.rmtree(FIXTURE_ROOT)

    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    LABEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Mentor's positive cases + our hard-negative probes, one labels.jsonl.
    all_cases = CASES + HARD_NEGATIVE_CASES

    with LABEL_PATH.open("w", encoding="utf-8") as label_file:
        for case in all_cases:
            case_dir = FIXTURE_ROOT / case["case_id"]
            case_dir.mkdir(parents=True, exist_ok=True)

            for relative_path, content in case["files"].items():
                target = case_dir / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(clean_text(content), encoding="utf-8")

            label_record = {
                "case_id": case["case_id"],
                "description": case["description"],
                "project_path": str(case_dir.relative_to(ROOT)),
                "scan_categories": case["scan_categories"],
                "expected_findings": case["expected_findings"],
                "expected_absent": case["expected_absent"],
            }

            label_file.write(json.dumps(label_record, ensure_ascii=False) + "\n")

    print(f"Generated {len(all_cases)} labeled fixture project(s)")
    print(f"  positive cases:      {len(CASES)}")
    print(f"  hard-negative cases: {len(HARD_NEGATIVE_CASES)}")
    print(f"Fixtures: {FIXTURE_ROOT}")
    print(f"Labels:   {LABEL_PATH}")


if __name__ == "__main__":
    generate_fixtures()
