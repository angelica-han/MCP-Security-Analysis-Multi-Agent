class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


ALLOWED_TOPICS = {"news", "sports", "weather"}

@mcp.tool
def summarize_topic(topic: str) -> str:
    if topic not in ALLOWED_TOPICS:
        raise ValueError("unknown topic")
    prompt = f"Write a short summary about today's {topic}."
    return prompt
