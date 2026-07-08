---
doc_id: kb-003
title: "CWE-918: Server-Side Request Forgery (SSRF)"
source: "https://cwe.mitre.org/data/definitions/918.html"
risk_type: network_ssrf
---

# CWE-918: Server-Side Request Forgery

The server fetches a URL supplied (in whole or part) by an external actor
without validating the destination. Typical Python patterns:
`requests.get(url)` where `url` is a tool parameter, or building URLs by
concatenating a user-supplied host.

## Why it matters in MCP servers

An MCP server usually runs on the user's machine or inside private
infrastructure. A fetch tool without destination checks lets an attacker pivot:
`http://169.254.169.254/` (cloud metadata credentials), `http://localhost:8080`
(internal admin panels), or internal IPs unreachable from outside.

## Remediation

- Allowlist permitted schemes (https only) and destination hosts/domains
- Resolve DNS and reject private/link-local ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8) — after redirects too
- Disable or strictly limit redirects; set timeouts
- Never forward internal responses verbatim into model context
