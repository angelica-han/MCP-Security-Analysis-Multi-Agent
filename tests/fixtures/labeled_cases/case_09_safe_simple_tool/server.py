class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def add_numbers(a: int, b: int) -> int:
    return a + b
