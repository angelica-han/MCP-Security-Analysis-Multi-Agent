---
doc_id: kb-001
title: "CWE-78: OS Command Injection"
source: "https://cwe.mitre.org/data/definitions/78.html"
risk_type: command_exec
---

# CWE-78: Improper Neutralization of Special Elements used in an OS Command

The software constructs all or part of an OS command using externally-influenced
input, but does not neutralize special elements that could modify the intended
command. Classic Python patterns: `subprocess.run(cmd, shell=True)` where `cmd`
contains user input, `os.system(f"...{param}...")`, or string concatenation
into shell commands.

## Why it matters in MCP servers

MCP tool parameters arrive from the model, which may be relaying untrusted user
or web content. Any tool parameter that reaches a shell without validation is
an injection path: an attacker can chain commands with `;`, `&&`, `|`, or
backticks.

## Remediation

- Avoid `shell=True`; pass arguments as a list: `subprocess.run(["git", "log", path])`
- If a shell is unavoidable, use `shlex.quote()` on every interpolated value
- Validate parameters against an allowlist of expected values or a strict regex
- Run with least privilege; never as root
