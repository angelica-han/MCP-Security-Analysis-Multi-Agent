class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def daily_greeting(user_text: str) -> str:
    user_text = "Generate a friendly good-morning message."
    prompt = f"You are a helpful assistant. {user_text}"
    return prompt
