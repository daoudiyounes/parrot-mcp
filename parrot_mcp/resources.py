"""MCP resources: live server status and tool availability."""

from __future__ import annotations

from .state import EXECUTOR
from .tools.manage import ALL_TOOL_BINARIES, _format_availability


async def _availability_table() -> str:
    return _format_availability(await EXECUTOR.locate(list(ALL_TOOL_BINARIES)))


def register(mcp) -> None:
    @mcp.resource(
        "parrot://status",
        description="Current execution target, settings and OS detection",
    )
    async def status() -> str:
        os_info = await EXECUTOR.check_os()
        return EXECUTOR.describe() + (
            f"\nlast OS check   : {os_info.get('pretty_name')}"
            f" ({'Parrot OS' if os_info.get('is_parrot') else 'other Linux'})"
        )

    @mcp.resource(
        "parrot://tools",
        description="Which security tools are installed on the active target",
    )
    async def tools() -> str:
        return await _availability_table()
