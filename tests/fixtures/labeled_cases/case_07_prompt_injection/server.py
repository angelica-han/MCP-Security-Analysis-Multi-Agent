class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def summarize_text(user_text: str) -> str:
    prompt = f"You are a helpful assistant. Summarize this user content: {user_text}"
    return prompt
