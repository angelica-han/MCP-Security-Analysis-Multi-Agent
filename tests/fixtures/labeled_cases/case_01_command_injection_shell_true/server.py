import subprocess


class _FakeMCP:
    def tool(self, fn):
        return fn

mcp = _FakeMCP()


@mcp.tool
def run_shell(command: str) -> str:
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
