"""Management tools: run_command gateway, execution targets, diagnostics, docker."""

from __future__ import annotations

import re
import shlex

from ..config import Config
from ..executor import Executor
from ..safety import check_command
from ..state import EXECUTOR
from . import run_shell

_LOCAL = Executor(Config())

_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

ALL_TOOL_BINARIES = (
    "nmap",
    "masscan",
    "amass",
    "sublist3r",
    "whois",
    "dnsrecon",
    "nikto",
    "whatweb",
    "gobuster",
    "wpscan",
    "dirsearch",
    "sslyze",
    "searchsploit",
    "sqlmap",
    "msfconsole",
    "hydra",
    "hashcat",
    "john",
    "anonsurf",
    "macchanger",
    "proxychains4",
    "theHarvester",
    "tor",
)


async def _switch_target(target: str) -> str:
    """Shared logic for set_execution_target: apply, probe, OS-check."""
    EXECUTOR.reset_connection()
    EXECUTOR.target = target
    lines = [EXECUTOR.describe()]
    if target != "local":
        probe = await EXECUTOR.run("echo __MCP_TARGET_OK__ $(uname -sr)", timeout=60)
        if probe.error:
            lines.append(f"connection test: FAILED - {probe.error}")
        elif probe.timed_out or "__MCP_TARGET_OK__" not in probe.stdout:
            lines.append(f"connection test: FAILED - unexpected output: {probe.stdout[:200]!r}")
        else:
            lines.append(
                f"connection test: OK - {probe.stdout.replace('__MCP_TARGET_OK__', '').strip()}"
            )
    os_info = await EXECUTOR.check_os(refresh=True)
    if os_info.get("is_parrot"):
        lines.append(f"OS check: {os_info.get('pretty_name')} - Parrot OS detected")
    else:
        lines.append(
            f"OS check: WARNING - target is {os_info.get('pretty_name')!r}, not Parrot OS. "
            "The server still works (generic Linux), but some tools may be missing; "
            "install them with apt or point the target at a Parrot machine."
        )
    if target == "docker" and not EXECUTOR.docker_container:
        lines.append(
            "note: ephemeral mode - every command gets a fresh container, so files, msf "
            "sessions and loot do NOT persist. For state, run docker_manage(action='create') "
            "then set_execution_target(target='docker', docker_container='<name>')."
        )
    return "\n".join(lines)


def _format_availability(found: dict[str, str | None]) -> str:
    return "\n".join(f"{'OK   ' if path else 'MISS '}{name}" for name, path in found.items())


async def _availability(names: list[str]) -> str:
    return "== tool availability ==\n" + _format_availability(await EXECUTOR.locate(names))


def register(mcp) -> None:
    @mcp.tool
    async def run_command(
        command: str,
        timeout_seconds: int | None = None,
        confirm_destructive: bool = False,
    ) -> str:
        """Run any shell command on the active target.

        This is the full-control entry point: anything installed on the target (mintupdate
        scripts, compilers, custom tools, python one-liners, apt, cat, echo...) can run here.
        Use the structured tools (nmap_scan, nikto_scan, ...) when you want curated defaults.

        Only guardrail: commands that would destroy the host itself (rm -rf /, dd to block
        devices, mkfs, fork bombs...) are refused until you pass confirm_destructive=true.
        Set PARROT_MCP_DISABLE_GUARDRAILS=1 to remove even that check.

        Args:
            command: the shell command to execute, e.g. "nmap -sV -p- 10.0.0.5" or
                "apt list --installed | grep -i metasploit".
            timeout_seconds: override the per-command timeout (default 900s, max 14400s).
            confirm_destructive: explicitly confirm a host-destructive command.
        """
        enabled = not EXECUTOR.disable_guardrails
        issues = check_command(command, enabled=enabled)
        if issues and not confirm_destructive:
            return (
                "REFUSED - this command matches host-destructive patterns:\n- "
                + "\n- ".join(issues)
                + f"\n\nCommand: {command}\n"
                + "Re-run with confirm_destructive=true if you REALLY mean it, or set "
                "PARROT_MCP_DISABLE_GUARDRAILS=1 to remove this check entirely."
            )
        result = await EXECUTOR.run(command, timeout_seconds)
        rendered = result.render()
        if issues:
            rendered = "WARNING: executed a confirmed host-destructive command.\n\n" + rendered
        return rendered

    @mcp.tool
    async def set_execution_target(
        target: str,
        ssh_host: str | None = None,
        ssh_port: int | None = None,
        ssh_user: str | None = None,
        ssh_password: str | None = None,
        ssh_key_path: str | None = None,
        ssh_key_passphrase: str | None = None,
        docker_image: str | None = None,
        docker_container: str | None = None,
    ) -> str:
        """Switch where commands run: local machine, a remote Parrot VM over SSH, or a Docker container.

        Passwords/keys can be given here or via PARROT_MCP_* environment variables;
        arguments override the environment for this session. After switching, a connection
        test and an OS check run automatically.

        Args:
            target: "local" | "ssh" | "docker".
            ssh_host: hostname/IP of the Parrot VM (target=ssh).
            ssh_port: SSH port (default 22).
            ssh_user: SSH user (default root or PARROT_MCP_SSH_USER).
            ssh_password: password auth (or use ssh_key_path / env).
            ssh_key_path: path to a private key file, e.g. "~/.ssh/id_ed25519".
            ssh_key_passphrase: passphrase for the key, if any.
            docker_image: image for the container (default parrotsec/security:latest).
            docker_container: container name to use - created on first use and reused, so
                files, msf sessions and loot survive between commands. Pass a NEW name to
                start fresh; pass "" for a throwaway container per command.
        """
        target = (target or "").strip().lower()
        if target not in {"local", "ssh", "docker"}:
            raise ValueError(f"unknown target {target!r}; choose from: local, ssh, docker")
        if ssh_host is not None:
            EXECUTOR.ssh_host = ssh_host
        if ssh_port is not None:
            EXECUTOR.ssh_port = int(ssh_port)
        if ssh_user is not None:
            EXECUTOR.ssh_user = ssh_user
        if ssh_password is not None:
            EXECUTOR.ssh_password = ssh_password
        if ssh_key_path is not None:
            EXECUTOR.ssh_key_path = ssh_key_path
        if ssh_key_passphrase is not None:
            EXECUTOR.ssh_key_passphrase = ssh_key_passphrase
        if docker_image is not None:
            EXECUTOR.docker_image = docker_image
        if docker_container is not None:
            EXECUTOR.docker_container = docker_container
        return await _switch_target(target)

    @mcp.tool
    async def get_execution_status() -> str:
        """Show the current execution target, connection settings, timeouts and OS detection."""
        os_info = await EXECUTOR.check_os()
        return EXECUTOR.describe() + (
            f"\nlast OS check   : {os_info.get('pretty_name')}"
            f" ({'Parrot OS' if os_info.get('is_parrot') else 'other Linux'})"
        )

    @mcp.tool
    async def system_info(timeout_seconds: int | None = None) -> str:
        """Full target snapshot: hostname, kernel, OS, user, disk, memory and which security tools are installed."""
        script = (
            'echo "== host =="; hostname; uname -a; head -2 /etc/os-release 2>/dev/null; id; uptime; '
            'echo; echo "== resources =="; df -h / 2>/dev/null | tail -1; free -h 2>/dev/null | head -2; '
            'echo; echo "== python =="; python3 --version 2>&1'
        )
        os_info = await EXECUTOR.check_os()
        notice = (
            ""
            if os_info.get("is_parrot")
            else (
                f"NOTE: target is {os_info.get('pretty_name')!r}, not Parrot OS - missing tools can be "
                "installed with `sudo apt install <tool>` (works for most Parrot/Kali tool names).\n\n"
            )
        )
        return (
            notice
            + await run_shell(script, timeout_seconds)
            + "\n\n"
            + await _availability(list(ALL_TOOL_BINARIES))
        )

    @mcp.tool
    async def check_tools(
        tools: list[str] | None = None, timeout_seconds: int | None = None
    ) -> str:
        """Check which security tools are installed on the target (OK/MISS per binary).

        Args:
            tools: specific binary names to check; omit to check the full bundled set.
            timeout_seconds: override the per-command timeout.
        """
        names = tools or list(ALL_TOOL_BINARIES)
        found = await EXECUTOR.locate(names)
        ok = sum(1 for p in found.values() if p)
        return (
            f"tools installed: {ok} | missing: {len(names) - ok}\n\n{_format_availability(found)}"
        )

    @mcp.tool
    async def docker_manage(
        action: str,
        container: str | None = None,
        image: str | None = None,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Manage the Docker side of Parrot MCP: pull/create/start/stop/remove/status a persistent Parrot container.

        After creating a container, switch to it with
        set_execution_target(target="docker", docker_container="<name>").
        These commands always run on the host Docker daemon (also when the
        execution target is already "docker").

        Args:
            action: "status" (container state), "pull" (image), "create" (detached container,
                kept alive with `sleep infinity`), "start", "stop", "remove".
            container: container name (default: PARROT_MCP_DOCKER_CONTAINER or "parrot-mcp").
            image: image to pull/create (default: PARROT_MCP_DOCKER_IMAGE, parrotsec/security:latest).
            extra_args: extra flags for "create", e.g. "--network host --cap-add NET_RAW
                --cap-add NET_ADMIN" (needed for SYN scans / macchanger inside the container)
                or "-v /path/on/host:/work" for shared files.
            timeout_seconds: override the per-command timeout (pull can be slow).
        """
        action = (action or "").strip().lower()
        if action not in {"status", "pull", "create", "start", "stop", "remove"}:
            raise ValueError(
                "unknown action; choose from: status, pull, create, start, stop, remove"
            )
        cname = container or EXECUTOR.docker_container or "parrot-mcp"
        img = image or EXECUTOR.docker_image
        runner = _LOCAL if EXECUTOR.target == "docker" else EXECUTOR
        if action == "status":
            listing = await runner.run(
                f"docker ps -a --filter name={shlex.quote(cname)}", timeout_seconds
            )
            state = await runner.run(
                f'docker inspect -f "{{{{.State.Status}}}}" {shlex.quote(cname)}',
                timeout_seconds,
            )
            return listing.render() + "\nstate: " + (state.stdout.strip() or "not-found")
        if action == "pull":
            return (await runner.run(f"docker pull {shlex.quote(img)}", timeout_seconds)).render()
        if action == "create":
            hint = (
                "\n\nNEXT STEP: set_execution_target(target='docker', docker_container="
                f"{shlex.quote(cname)}) to run commands inside it."
            )
            flags = " ".join(shlex.quote(tok) for tok in shlex.split(extra_args or ""))
            result = await runner.run(
                f"docker run -d --name {shlex.quote(cname)} {flags} {shlex.quote(img)} sleep infinity",
                timeout_seconds,
            )
            return result.render() + (hint if result.exit_code == 0 else "")
        command = f"docker {action} {shlex.quote(cname)}"
        if action == "remove":
            command = f"docker rm -f {shlex.quote(cname)}"
        return (await runner.run(command, timeout_seconds)).render()

    @mcp.tool
    async def list_files(
        directory: str = ".",
        pattern: str | None = None,
        timeout_seconds: int | None = None,
    ) -> str:
        """List a directory on the target.

        Args:
            directory: directory path on the target, e.g. "/work" or "/root/scans".
            pattern: optional glob matching names in that directory, e.g. "*.nmap".
            timeout_seconds: override the per-command timeout.
        """
        directory = shlex.quote(directory.rstrip("/") or "/")
        if pattern:
            script = f"find {directory} -maxdepth 1 -name {shlex.quote(pattern.strip())} -printf '%M %10s  %p\\n'"
        else:
            script = f"ls -la {directory}"
        return await run_shell(script, timeout_seconds)

    @mcp.tool
    async def get_file_info(path: str, timeout_seconds: int | None = None) -> str:
        """File type, size and hashes (SHA256, MD5) for a file on the target.

        Args:
            path: file path on the target.
            timeout_seconds: override the per-command timeout.
        """
        quoted = shlex.quote(path)
        script = (
            f"stat -c '%n  %s bytes' {quoted}; file {quoted}; sha256sum {quoted}; md5sum {quoted}"
        )
        return await run_shell(script, timeout_seconds)

    @mcp.tool
    async def get_tool_help(tool: str, timeout_seconds: int | None = None) -> str:
        """Show the usage/help output of any tool installed on the target.

        Use it to learn the flags of a Parrot tool before wrapping it in a
        run_command call - there are hundreds of tools, far more than the
        structured wrappers cover. Tries --help, then -h, then runs the tool
        with no arguments. Help calls are capped at 300s.

        Args:
            tool: binary name, e.g. "responder", "crackmapexec", "ffuf".
            timeout_seconds: override the per-command timeout (default 60s, max 300s).
        """
        name = (tool or "").strip()
        if not _TOOL_NAME.match(name):
            raise ValueError(
                f"invalid tool name {tool!r}: expected a binary name such as 'nmap' or 'ffuf'"
            )
        quoted = shlex.quote(name)
        script = (
            f"command -v {quoted} >/dev/null 2>&1 || {{ echo 'not installed: {name}'; exit 127; }}; "
            f"for flag in --help -h; do "
            f'out=$({quoted} "$flag" 2>&1) && [ -n "$out" ] && {{ printf \'%s\\n\' "$out"; exit 0; }}; '
            f"done; "
            f"{quoted} 2>&1 | head -100"
        )
        return await run_shell(script, min(int(timeout_seconds or 60), 300))
