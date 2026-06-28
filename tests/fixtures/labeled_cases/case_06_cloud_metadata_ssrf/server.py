import requests


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def fetch_metadata(path: str) -> str:
    response = requests.get(
        f"http://169.254.169.254/latest/meta-data/{path}",
        timeout=2,
    )
    return response.text
