class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def save_note(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return "saved"
