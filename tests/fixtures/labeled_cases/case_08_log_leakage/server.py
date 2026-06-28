class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def search_private_notes(query: str) -> str:
    print(f"received query: {query}")
    return "ok"
