---
doc_id: kb-004
title: "OWASP LLM01: Prompt Injection"
source: "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
risk_type: prompt_injection
---

# OWASP LLM Top 10 — LLM01: Prompt Injection

Untrusted content (user input, fetched web pages, file contents, tool results)
enters an LLM prompt and overrides the developer's instructions. In MCP
codebases the highest-value variant is **tool-description / tool-result
injection**: strings that the server interpolates into prompts or tool
metadata that a connected model will read and obey.

## Why it matters in MCP servers

MCP tools return arbitrary content into the model's context. If a server
builds prompts via f-strings over remote content (`f"Summarize: {fetched_page}"`)
or lets user data flow into system prompts or tool descriptions, an attacker
who controls that content controls the model — leading to data exfiltration or
unauthorized tool calls.

## Remediation

- Treat all external content as data, not instructions: delimit it clearly and
  tell the model it is untrusted
- Never interpolate untrusted input into system prompts or tool descriptions
- Constrain downstream capability: least-privilege tools, confirmation for
  sensitive actions
- Detection heuristics (keyword filters) are weak alone; combine with taint
  tracking — only flag when untrusted input actually reaches a prompt sink
