import requests


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def fetch_url(url: str) -> str:
    response = requests.get(url, timeout=5)
    return response.text
