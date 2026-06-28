class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def record_feedback(user_text: str) -> str:
    message = f"Thank you for your feedback: {user_text}"
    return message
