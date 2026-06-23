"""
llm.py — Shared LLM access layer.

The pipeline decides "which model / whose key" in exactly one place: here.
Both the reporter and (later) the evaluator call get_llm(), so model choice
and key handling live in a single spot.

Design rules:
- The model is chosen via the LLM_MODEL environment variable, e.g.:
      anthropic:claude-3-5-sonnet-latest
      openai:gpt-4o
      google_genai:gemini-1.5-pro
  Switching provider means editing .env only — never the code.
- If no key is configured or the provider package is missing, get_llm()
  returns None. Callers MUST treat None as "LLM unavailable" and fall back
  to deterministic behaviour. This keeps the whole pipeline runnable with
  zero credentials — the LLM is an enhancement, not a dependency.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache

try:
    from dotenv import load_dotenv

    load_dotenv()  # read keys from .env into the environment
except ImportError:
    pass  # dotenv not installed → fall back to system environment variables


# Default model; overridden by LLM_MODEL in .env if set.
DEFAULT_MODEL = "anthropic:claude-3-5-sonnet-latest"


@lru_cache(maxsize=4)
def get_llm(model: str | None = None, temperature: float = 0.2):
    """
    Return a LangChain chat model, or None if one cannot be constructed.

    Cached with lru_cache so the client is built once per (model, temperature).
    temperature defaults to 0.2: security reports should be stable and
    reproducible — the same findings should yield near-identical wording.
    """
    model = model or os.getenv("LLM_MODEL", DEFAULT_MODEL)
    try:
        from langchain.chat_models import init_chat_model

        # timeout + max_retries are accepted by all three providers (OpenAI,
        # Anthropic, Google). The timeout bounds the call so a slow or stuck
        # request can never freeze the pipeline — on timeout it raises and the
        # caller falls back to the deterministic path.
        return init_chat_model(
            model,
            temperature=temperature,
            timeout=60,
            max_retries=2,
        )
    except Exception as e:
        # Missing package, bad key, or malformed model string — all non-fatal.
        # Emit a hint to stderr and let the caller fall back to deterministic output.
        print(f"[llm] LLM unavailable ({e}); falling back to deterministic logic.", file=sys.stderr)
        return None
