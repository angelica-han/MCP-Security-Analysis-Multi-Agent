import subprocess


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


ALLOWED_CMDS = {
    "status": ["systemctl", "status"],
    "uptime": ["uptime"],
}

@mcp.tool
def run_diagnostic(name: str) -> str:
    if name not in ALLOWED_CMDS:
        raise ValueError("unknown diagnostic")
    result = subprocess.run(
        ALLOWED_CMDS[name],
        shell=False,
        capture_output=True,
        text=True,
    )
    return result.stdout
