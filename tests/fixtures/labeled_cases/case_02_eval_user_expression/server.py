class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def calculate(expression: str):
    return eval(expression)
