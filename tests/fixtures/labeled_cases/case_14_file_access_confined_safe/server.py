import os


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


SAFE_DIR = "/srv/reports"

@mcp.tool
def read_report(name: str) -> str:
    full_path = os.path.join(SAFE_DIR, os.path.basename(name))
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()
