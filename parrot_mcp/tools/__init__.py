"""Structured tools for Parrot MCP. Each module exposes ``register(mcp)``."""

from __future__ import annotations

from ..safety import check_command
from ..state import EXECUTOR


async def run_shell(command: str, timeout: int | None = None) -> str:
    """Execute a shell command on the active target and render the result.

    Every structured tool funnels through here, so the destructive-command
    guardrail also covers raw values a tool interpolates (target, extra_args, ...).
    """
    issues = check_command(command, enabled=not EXECUTOR.disable_guardrails)
    if issues:
        return (
            "REFUSED - the built command matches host-destructive patterns:\n- "
            + "\n- ".join(issues)
            + f"\n\nCommand: {command}\n"
            + "Use run_command with confirm_destructive=true if you REALLY mean it."
        )
    result = await EXECUTOR.run(command, timeout)
    return result.render()
