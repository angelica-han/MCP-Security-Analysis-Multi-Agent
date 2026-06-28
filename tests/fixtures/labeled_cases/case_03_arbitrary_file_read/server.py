class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
