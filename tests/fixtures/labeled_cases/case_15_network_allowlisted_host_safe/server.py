import requests


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


ALLOWED_HOSTS = {"api.example.com", "data.example.com"}

@mcp.tool
def fetch_status(host: str) -> str:
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    response = requests.get(f"https://{host}/status", timeout=5)
    return response.text
