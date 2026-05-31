# Vulnerable Sample MCP Server

This directory contains a deliberately vulnerable MCP server used as a scan target
for the security analysis pipeline.

It is not intended to be run in production. The goal is to provide realistic code
patterns that static scanners and agents can detect with file, line, and snippet
evidence.

## Version Strategy

The sample uses the familiar `FastMCP` Python shape because it is simple and easy
to scan. The vulnerabilities are intentionally chosen to remain relevant across
MCP versions:

| Area | Why it matters |
| --- | --- |
| Command execution | Tools can pass model/user-controlled arguments into shell commands. |
| File access | Tools can expose local filesystem reads without path normalization. |
| Network requests | Tools can be abused for SSRF or internal network probing. |
| Prompt construction | Tool outputs or user notes can inject instructions into later LLM calls. |
| Legacy lifecycle state | Older stateful MCP/session designs can leak cross-user state. |
| Explicit handles | Newer stateless MCP designs push continuity into server-minted handles, which can create IDOR-style risks if handles are predictable or authorization is missing. |

For the first demo, scan this directory and produce an evidence-backed report.

## Expected Findings

- `run_shell`: command injection through `subprocess.run(..., shell=True)`.
- `read_project_file`: path traversal through unchecked user-controlled paths.
- `fetch_url`: SSRF risk through unrestricted `requests.get(url)`.
- `draft_summary_prompt`: prompt injection risk through raw user notes embedded in a prompt.
- `create_workspace` / `read_workspace`: predictable state handles and missing owner checks.
- `remember_last_result` / `get_last_result`: global state shared across callers.

