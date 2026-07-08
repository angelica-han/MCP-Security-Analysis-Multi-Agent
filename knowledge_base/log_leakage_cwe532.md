---
doc_id: kb-005
title: "CWE-532: Insertion of Sensitive Information into Log File"
source: "https://cwe.mitre.org/data/definitions/532.html"
risk_type: lifecycle_leak
---

# CWE-532: Sensitive Information in Log Files

The software writes sensitive data — credentials, tokens, session identifiers,
full request payloads — into logs. Related lifecycle issues: session state that
outlives the session (CWE-459 incomplete cleanup) and temp files left behind
with sensitive content.

## Why it matters in MCP servers

MCP servers proxy user data and hold API keys. `logger.info(f"request: {params}")`
on a tool that receives file contents or auth tokens persists that data to disk
outside any access control. Long-lived server processes that cache per-session
state can also leak one session's data into the next.

## Remediation

- Log event metadata, not payloads; redact known-sensitive fields before logging
- Never log environment variables, headers, or full tool parameters
- Clear per-session caches/state on session end; use context managers for temp files
- Set log file permissions restrictively and rotate with retention limits
