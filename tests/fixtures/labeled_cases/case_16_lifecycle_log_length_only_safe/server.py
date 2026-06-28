class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def search_notes(query: str) -> str:
    print(f"search_notes called, query length={len(query)}")
    return "ok"
