"""Runs every command for every tool, on one of three targets.

* ``local``  - the machine hosting the server (Parrot install, WSL, a container).
* ``ssh``    - a remote Parrot machine, with a private key, inline key, or password.
* ``docker`` - a named container created on first use and reused, so state
  survives between commands. Set the container name to "" for one container
  per command.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import paramiko

log = logging.getLogger("parrot_mcp")

MAX_TIMEOUT = 14_400

_MISSING_BINARY = re.compile(
    r"(?:(?:/bin/)?(?:ba)?sh: (?:line )?\d+: )?([\w.+-]+): (?:command )?not found"
)
_NOT_INSTALLED = re.compile(r"^not installed: ([\w.+-]+)$", re.MULTILINE)

_PACKAGE_ALIASES = {
    "searchsploit": "exploitdb",
    "theHarvester": "theharvester",
    "anonsurf": "anonsurf-cli",
}


@dataclass
class CommandResult:
    """Outcome of one command executed on the active target."""

    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_sec: float
    target: str
    timed_out: bool = False
    error: str | None = None

    def render(self) -> str:
        status = "timeout" if self.timed_out else str(self.exit_code)
        parts = [
            f"$ {self.command}",
            f"[target={self.target}] exit={status} | {self.duration_sec:.1f}s",
        ]
        if self.error:
            parts.append(f"--- error ---\n{self.error}")
        if self.stdout:
            parts.append(f"--- stdout ---\n{self.stdout}")
        if self.stderr:
            parts.append(f"--- stderr ---\n{self.stderr}")
        hint = self._missing_tool_hint()
        if hint:
            parts.append(hint)
        return "\n".join(parts)

    def _missing_tool_hint(self) -> str:
        if self.exit_code != 127:
            return ""
        match = _MISSING_BINARY.search(self.stderr) or _NOT_INSTALLED.search(self.stdout)
        if not match:
            return ""
        binary = match.group(1)
        package = _PACKAGE_ALIASES.get(binary, binary)
        return (
            f"note: '{binary}' is not installed on the target. Install it with "
            f"`sudo apt install {package}` (check the package name with "
            f"`apt-cache search {binary}`), or run the tool through run_command "
            f"if it lives somewhere else on PATH."
        )


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


def _clip(text: str, limit: int) -> str:
    """Keep head + tail of oversized output so the LLM context stays usable."""
    if len(text) <= limit:
        return text
    keep = max(limit // 2, 200)
    hidden = len(text) - 2 * keep
    return text[:keep] + f"\n\n... [output clipped: {hidden} chars hidden] ...\n\n" + text[-keep:]


class Executor:
    """Runs shell commands on the active target (local / ssh / docker)."""

    def __init__(self, config) -> None:
        self.target = config.target
        self.timeout = config.timeout
        self.max_output = config.max_output
        self.disable_guardrails = config.disable_guardrails
        self.ssh_host = config.ssh_host
        self.ssh_port = config.ssh_port
        self.ssh_user = config.ssh_user
        self.ssh_password = config.ssh_password
        self.ssh_key_path = config.ssh_key_path
        self.ssh_key_passphrase = config.ssh_key_passphrase
        self.ssh_key_data = config.ssh_key_data
        self.ssh_strict_host_key = config.ssh_strict_host_key
        self.docker_image = config.docker_image
        self.docker_container = config.docker_container
        self.audit_log = config.audit_log
        self._ssh: paramiko.SSHClient | None = None
        self._ssh_lock = asyncio.Lock()
        self._temp_keys: list[str] = []
        self._last_os: dict = {}
        self._audit_lock = asyncio.Lock()

    async def run(self, command: str, timeout: int | None = None) -> CommandResult:
        timeout = max(1, min(int(timeout or self.timeout), MAX_TIMEOUT))
        started = time.monotonic()
        try:
            if self.target == "local":
                stdout, stderr, code, timed_out = await self._run_local(command, timeout)
            elif self.target == "ssh":
                stdout, stderr, code, timed_out = await self._run_ssh(command, timeout)
            elif self.target == "docker":
                stdout, stderr, code, timed_out = await self._run_docker(command, timeout)
            else:
                raise RuntimeError(f"unknown execution target {self.target!r}")
        except RuntimeError as exc:
            result = CommandResult(
                command=command,
                exit_code=None,
                stdout="",
                stderr="",
                duration_sec=time.monotonic() - started,
                target=self.target,
                error=str(exc),
            )
            await self._audit(result)
            return result
        result = CommandResult(
            command=command,
            exit_code=code,
            stdout=_clip(stdout, self.max_output),
            stderr=_clip(stderr, self.max_output),
            duration_sec=time.monotonic() - started,
            target=self.target,
            timed_out=timed_out,
        )
        await self._audit(result)
        return result

    async def _audit(self, result: CommandResult) -> None:
        """Append one line per command when PARROT_MCP_AUDIT_LOG is set.

        Records the command and outcome, never stdout (which may hold secrets).
        A failing log is reported once on stderr, not raised: auditing must not
        break the command the user asked for.
        """
        if not self.audit_log:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": result.target,
            "command": result.command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_sec": round(result.duration_sec, 3),
            "error": result.error,
        }
        line = json.dumps(entry) + "\n"
        async with self._audit_lock:
            try:
                await asyncio.to_thread(self._append_audit, line)
            except OSError as exc:
                log.warning("audit log write failed (%s): %s", self.audit_log, exc)

    def _append_audit(self, line: str) -> None:
        path = os.path.expanduser(self.audit_log)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        mode = 0o600
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line)

    async def check_os(self, refresh: bool = False) -> dict:
        """Detect the OS of the active target (used for the Parrot fallback notice)."""
        if self._last_os and not refresh:
            return self._last_os
        result = await self.run("head -5 /etc/os-release 2>/dev/null || uname -s", timeout=30)
        pretty = "unknown"
        for line in result.stdout.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
                break
        if pretty == "unknown":
            first = result.stdout.strip().splitlines()
            pretty = first[0] if first else "unknown"
        info = {
            "pretty_name": pretty,
            "is_parrot": "parrot" in pretty.lower(),
            "target": self.target,
        }
        self._last_os = info
        return info

    async def locate(self, names: list[str]) -> dict[str, str | None]:
        """Resolve binaries to paths on the active target (None when missing).

        Uses shutil.which for the local target so it also works on Windows,
        where the POSIX ``command -v`` probe below does not.
        """
        if self.target == "local":
            return {name: shutil.which(name) for name in names}
        script = " ".join(
            f'printf "%s\\t%s\\n" "$(command -v {shlex.quote(name)} || echo)" {shlex.quote(name)};'
            for name in names
        )
        result = await self.run(script, timeout=60)
        if result.error or result.timed_out or (result.exit_code and not result.stdout.strip()):
            raise RuntimeError(
                result.error or f"target unreachable (probe exit {result.exit_code})"
            )
        found: dict[str, str | None] = {}
        for line in result.stdout.splitlines():
            path, _, name = line.partition("\t")
            found[name.strip()] = path.strip() or None
        return {name: found.get(name) for name in names}

    def describe(self) -> str:
        lines = [f"execution target : {self.target}"]
        if self.target == "ssh":
            method = (
                "password"
                if self.ssh_password
                else "private key"
                if (self.ssh_key_path or self.ssh_key_data)
                else "agent / default keys"
            )
            lines += [
                f"ssh endpoint     : {self.ssh_user}@{self.ssh_host}:{self.ssh_port}",
                f"ssh auth         : {method}" + (" (password: ***)" if self.ssh_password else ""),
                "host key policy  : "
                + (
                    "strict (known_hosts only)"
                    if self.ssh_strict_host_key
                    else "auto-add (accept new hosts)"
                ),
            ]
        elif self.target == "docker":
            lines += [
                f"docker image     : {self.docker_image}"
                + ("" if self.docker_container else " (ephemeral container per command)"),
                f"container        : {self.docker_container or '(none)'}",
            ]
        lines += [
            f"default timeout  : {self.timeout}s",
            f"max output       : {self.max_output} chars/command",
            "guardrails       : "
            + (
                "disabled - every command runs as-is"
                if self.disable_guardrails
                else "on - host-destructive commands are refused (run_command can confirm)"
            ),
        ]
        if self._last_os:
            name = self._last_os.get("pretty_name")
            mark = (
                "Parrot OS detected"
                if self._last_os.get("is_parrot")
                else f"NOT Parrot OS ({name})"
            )
            lines.append(f"os check         : {name} - {mark}")
        return "\n".join(lines)

    def reset_connection(self) -> None:
        self._close_ssh()
        self._last_os = {}

    async def _run_local(self, command: str, timeout: int):
        is_posix = os.name == "posix"
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                **({"start_new_session": True} if is_posix else {}),
            )
        except OSError as exc:
            raise RuntimeError(f"failed to spawn process: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
            return _decode(out), _decode(err), proc.returncode, False
        except (asyncio.TimeoutError, TimeoutError):
            with contextlib.suppress(ProcessLookupError):
                if is_posix:
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    with contextlib.suppress(OSError):
                        killer = await asyncio.create_subprocess_exec(
                            "taskkill",
                            "/F",
                            "/T",
                            "/PID",
                            str(proc.pid),
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        await killer.wait()
            out, err = await proc.communicate()
            return _decode(out), _decode(err), None, True

    async def _run_ssh(self, command: str, timeout: int):
        async with self._ssh_lock:
            try:
                client = await asyncio.to_thread(self._ensure_ssh_client)
            except (paramiko.SSHException, OSError) as exc:
                raise RuntimeError(
                    f"SSH connection to {self.ssh_user}@{self.ssh_host}:{self.ssh_port} failed: {exc}"
                ) from exc
            remote = f"timeout {timeout}s bash -c {shlex.quote(command)}"

            def _exec():
                _stdin, stdout, stderr = client.exec_command(remote, timeout=timeout + 15)
                out = stdout.read()
                err = stderr.read()
                code: int | None
                try:
                    code = stdout.channel.recv_exit_status()
                except (EOFError, paramiko.SSHException):
                    code = None
                return out, err, code

            try:
                out, err, code = await asyncio.wait_for(asyncio.to_thread(_exec), timeout + 20)
            except (asyncio.TimeoutError, TimeoutError):
                await asyncio.to_thread(self._close_ssh)
                return (
                    "",
                    f"command exceeded {timeout}s; SSH channel closed",
                    None,
                    True,
                )
            except paramiko.SSHException as exc:
                raise RuntimeError(f"SSH command failed: {exc}") from exc
            return _decode(out), _decode(err), code, False

    def _ensure_ssh_client(self) -> paramiko.SSHClient:
        if self._ssh is not None:
            transport = self._ssh.get_transport()
            if transport is not None and transport.is_active():
                return self._ssh
            self._close_ssh()
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.RejectPolicy() if self.ssh_strict_host_key else paramiko.AutoAddPolicy()
        )
        kwargs: dict = {
            "hostname": self.ssh_host,
            "port": self.ssh_port,
            "username": self.ssh_user,
            "timeout": 15,
            "banner_timeout": 30,
            "auth_timeout": 30,
            "allow_agent": True,
            "look_for_keys": True,
        }
        key_file: str | None = None
        if self.ssh_key_path:
            key_file = os.path.expanduser(self.ssh_key_path)
        elif self.ssh_key_data:
            key_file = self._materialize_key_data(self.ssh_key_data)
        if key_file:
            kwargs.update(
                key_filename=key_file,
                passphrase=self.ssh_key_passphrase or None,
                allow_agent=False,
                look_for_keys=False,
            )
        elif self.ssh_password:
            kwargs.update(password=self.ssh_password, allow_agent=False, look_for_keys=False)
        client.connect(**kwargs)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        self._ssh = client
        return client

    def _materialize_key_data(self, key_data: str) -> str:
        """Write an inline PEM key to a secure temp file (cleaned up on close)."""
        if "\\n" in key_data and "\n" not in key_data:
            key_data = key_data.replace("\\n", "\n")
        fd, path = tempfile.mkstemp(prefix="parrot-mcp-key-", suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(key_data if key_data.endswith("\n") else key_data + "\n")
        os.chmod(path, 0o600)
        self._temp_keys.append(path)
        return path

    def _close_ssh(self) -> None:
        if self._ssh is not None:
            with contextlib.suppress(Exception):
                self._ssh.close()
        self._ssh = None
        for path in self._temp_keys:
            with contextlib.suppress(OSError):
                os.unlink(path)
        self._temp_keys.clear()

    async def _run_docker(self, command: str, timeout: int):
        await self._ensure_docker_ready()
        if self.docker_container:
            argv = [
                "docker",
                "exec",
                self.docker_container,
                "timeout",
                f"{timeout}s",
                "bash",
                "-c",
                command,
            ]
        else:
            argv = [
                "docker",
                "run",
                "--rm",
                self.docker_image,
                "timeout",
                f"{timeout}s",
                "bash",
                "-c",
                command,
            ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RuntimeError(f"failed to run docker: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout + 10)
            return _decode(out), _decode(err), proc.returncode, False
        except (asyncio.TimeoutError, TimeoutError):
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            out, err = await proc.communicate()
            return _decode(out), _decode(err), None, True

    async def _ensure_docker_ready(self) -> None:
        code, out, err = await self._docker_cli(
            ["docker", "info", "--format", "{{.ServerVersion}}"], 20
        )
        if code != 0:
            raise RuntimeError(
                f"Docker daemon not reachable: {err[:300] or 'docker command failed'}"
            )
        if self.docker_container:
            code, out, _ = await self._docker_cli(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    self.docker_container,
                ],
                20,
            )
            if code != 0:
                code, _, err = await self._docker_cli(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        self.docker_container,
                        self.docker_image,
                        "sleep",
                        "infinity",
                    ],
                    300,
                )
                if code != 0:
                    raise RuntimeError(
                        f"failed to create container {self.docker_container!r}: {err[:300]}"
                    )
                return
            if out.strip() == "false":
                code, _, err = await self._docker_cli(
                    ["docker", "start", self.docker_container], 60
                )
                if code != 0:
                    raise RuntimeError(
                        f"failed to start container {self.docker_container!r}: {err[:300]}"
                    )

    async def _docker_cli(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RuntimeError(f"docker CLI not available: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            out, err = await proc.communicate()
            return 124, "", _decode(err)
        return proc.returncode, _decode(out), _decode(err)
