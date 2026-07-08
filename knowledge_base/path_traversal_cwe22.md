---
doc_id: kb-002
title: "CWE-22: Path Traversal"
source: "https://cwe.mitre.org/data/definitions/22.html"
risk_type: file_access
---

# CWE-22: Improper Limitation of a Pathname to a Restricted Directory

The software uses external input to construct a pathname without neutralizing
sequences such as `../` that can resolve outside the intended directory.
Typical Python patterns: `open(os.path.join(base_dir, user_path))` without a
containment check, or reading files whose path comes directly from a tool
parameter.

## Why it matters in MCP servers

File-reading tools are among the most common MCP capabilities. A traversal in a
file tool lets the model (or whoever is steering it) read `~/.ssh/id_rsa`,
`.env` files, browser cookies — anything the server process can see.

## Remediation

- Resolve then verify containment: `Path(base, p).resolve().is_relative_to(Path(base).resolve())`
- Maintain an allowlist of readable roots; deny dotfiles and sensitive dirs by default
- Reject inputs containing `..` early, but never rely on that alone (encoding tricks)
- Serve file contents with size limits to bound blast radius
