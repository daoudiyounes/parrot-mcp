"""Anonymity & OSINT tools: anonsurf, macchanger, proxychains, tor status, theHarvester.

These wrap Parrot OS's anonymity stack. Most actions need root - run the
executor as root (root user on the VM, root in the container, or via sudo).
Anonsurf and Tor need a real systemd host; inside a container use the `ssh`
target (or proxychains if a SOCKS proxy is already reachable).
"""

from __future__ import annotations

import shlex

from . import run_shell

ANONSURF_ACTIONS = {"start", "stop", "restart", "status", "change"}
MACCHANGER_MODES = {"show", "random", "specific", "restore"}


def build_macchanger_command(interface: str, mode: str, mac: str | None) -> str:
    mode = (mode or "show").strip().lower()
    if mode not in MACCHANGER_MODES:
        raise ValueError(f"unknown mode {mode!r}; choose from: {', '.join(MACCHANGER_MODES)}")
    if mode == "show":
        return f"macchanger -s {shlex.quote(interface)}"
    if mode == "restore":
        return (
            f"ip link set dev {shlex.quote(interface)} down"
            f" && macchanger -p {shlex.quote(interface)}"
            f" && ip link set dev {shlex.quote(interface)} up"
        )
    if mode == "specific":
        if not mac:
            raise ValueError(
                "mode='specific' requires the 'mac' argument, e.g. '02:11:22:33:44:55'"
            )
        flag, mac_part = "-m", shlex.quote(mac)
    else:
        flag, mac_part = "-r", ""
    down = f"ip link set dev {shlex.quote(interface)} down"
    up = f"ip link set dev {shlex.quote(interface)} up"
    return f"{down} && macchanger {flag} {mac_part} {shlex.quote(interface)} && {up}".replace(
        "  ", " "
    ).strip()


def register(mcp) -> None:
    @mcp.tool
    async def anonsurf_control(
        action: str,
        timeout_seconds: int | None = None,
    ) -> str:
        """Control Parrot OS's Anonsurf (system-wide Tor routing) - start/stop/restart/status/change.

        Args:
            action: "start" (route everything through Tor), "stop" (back to clearnet),
                "restart", "status" (tor + IP check), "change" (new Tor identity + new MAC).
            timeout_seconds: override the per-command timeout.
        """
        action = (action or "").strip().lower()
        if action not in ANONSURF_ACTIONS:
            raise ValueError(
                f"unknown action {action!r}; choose from: {', '.join(ANONSURF_ACTIONS)}"
            )
        return await run_shell(f"anonsurf {action}", timeout_seconds)

    @mcp.tool
    async def macchanger_spoof(
        interface: str,
        mode: str = "random",
        mac: str | None = None,
        timeout_seconds: int | None = None,
    ) -> str:
        """Show or spoof the MAC address of a network interface (needs root).

        Args:
            interface: interface name, e.g. "eth0", "wlan0" (see `ip a` via run_command).
            mode: "show" (current MAC), "random" (random vendor-less MAC), "specific"
                (use the 'mac' argument), "restore" (back to the burned-in hardware MAC).
            mac: target MAC for mode="specific", e.g. "02:11:22:33:44:55".
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(build_macchanger_command(interface, mode, mac), timeout_seconds)

    @mcp.tool
    async def proxychains_exec(
        command: str,
        quiet: bool = True,
        timeout_seconds: int | None = None,
    ) -> str:
        """Run a command through proxychains, which uses Tor unless its config says otherwise.

        Requires the Tor SOCKS proxy to be up - call anonsurf_control(action='start') or
        `systemctl start tor` first, then verify with tor_status.

        Args:
            command: command line to route through the proxy, e.g. "curl -s https://api.ipify.org".
            quiet: silence proxychains' own log lines (-q).
            timeout_seconds: override the per-command timeout.
        """
        flag = " -q" if quiet else ""
        quoted = shlex.quote(command)
        script = (
            f"if command -v proxychains4 >/dev/null 2>&1; then proxychains4{flag} bash -c {quoted}; "
            f"else proxychains bash -c {quoted}; fi"
        )
        return await run_shell(script, timeout_seconds)

    @mcp.tool
    async def tor_status(timeout_seconds: int | None = None) -> str:
        """Check whether the Tor service is running and whether traffic exits via the Tor network."""
        command = (
            'echo "tor service: $(systemctl is-active tor 2>/dev/null || echo unknown)" ; '
            "curl -s --max-time 15 https://check.torproject.org/api/ip || true"
        )
        return await run_shell(command, timeout_seconds)

    @mcp.tool
    async def theharvester_search(
        domain: str,
        sources: str = "bing",
        limit: int = 100,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """OSINT harvest of emails, names, subdomains and hosts with theHarvester.

        Args:
            domain: target domain, e.g. "example.com".
            sources: comma-separated engines, e.g. "bing,duckduckgo,github,crtsh".
            limit: max results per source.
            extra_args: extra raw theHarvester flags.
            timeout_seconds: override the per-command timeout.
        """
        command = f"theHarvester -d {shlex.quote(domain)} -b {shlex.quote(sources)} -l {int(limit)}"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)
