"""Environment-driven configuration for the Parrot MCP server.

Every value can be set through ``PARROT_MCP_*`` environment variables so the
server works equally well when started manually, launched from a client
config (claude_desktop_config.json, .mcp.json, Cline settings, ...) or
inside a Docker container.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """All runtime settings for the server and the command executor."""

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8420
    path: str = "/mcp"
    auth_token: str = ""

    target: str = "local"
    timeout: int = 900
    max_output: int = 30_000
    disable_guardrails: bool = False

    ssh_host: str = "127.0.0.1"
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str = ""
    ssh_key_path: str = ""
    ssh_key_passphrase: str = ""
    ssh_key_data: str = ""
    ssh_strict_host_key: bool = False

    docker_image: str = "parrotsec/security:latest"
    docker_container: str = "parrot-mcp"

    audit_log: str = ""

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            transport=_env("PARROT_MCP_TRANSPORT", "stdio").lower(),
            host=_env("PARROT_MCP_HOST", "127.0.0.1"),
            port=_env_int("PARROT_MCP_PORT", 8420),
            path=_env("PARROT_MCP_PATH", "/mcp") or "/mcp",
            auth_token=_env("PARROT_MCP_AUTH_TOKEN"),
            target=_env("PARROT_MCP_TARGET", "local").lower(),
            timeout=_env_int("PARROT_MCP_TIMEOUT", 900),
            max_output=_env_int("PARROT_MCP_MAX_OUTPUT", 30_000),
            disable_guardrails=_env_bool("PARROT_MCP_DISABLE_GUARDRAILS"),
            ssh_host=_env("PARROT_MCP_SSH_HOST", "127.0.0.1"),
            ssh_port=_env_int("PARROT_MCP_SSH_PORT", 22),
            ssh_user=_env("PARROT_MCP_SSH_USER", "root"),
            ssh_password=_env("PARROT_MCP_SSH_PASSWORD"),
            ssh_key_path=_env("PARROT_MCP_SSH_KEY_PATH"),
            ssh_key_passphrase=_env("PARROT_MCP_SSH_KEY_PASSPHRASE"),
            ssh_key_data=_env("PARROT_MCP_SSH_KEY_DATA"),
            ssh_strict_host_key=_env_bool("PARROT_MCP_SSH_STRICT_HOST_KEY"),
            docker_image=_env("PARROT_MCP_DOCKER_IMAGE", "parrotsec/security:latest"),
            docker_container=_env("PARROT_MCP_DOCKER_CONTAINER", "parrot-mcp"),
            audit_log=_env("PARROT_MCP_AUDIT_LOG"),
        )

    def validate(self) -> list[str]:
        """Return human-readable problems with the configuration (empty if OK)."""
        problems: list[str] = []
        if self.transport not in {"stdio", "http"}:
            problems.append(f"unknown transport {self.transport!r} (use stdio|http)")
        if self.target not in {"local", "ssh", "docker"}:
            problems.append(f"unknown target {self.target!r} (use local|ssh|docker)")
        if not 1 <= self.timeout <= 14_400:
            problems.append("timeout must be between 1 and 14400 seconds")
        if self.max_output < 1_000:
            problems.append("max_output must be at least 1000 chars")
        if (
            self.transport == "http"
            and not self.auth_token
            and self.host not in {"127.0.0.1", "localhost", "::1"}
        ):
            problems.append(
                f"HTTP bound to {self.host!r} needs PARROT_MCP_AUTH_TOKEN "
                "(or bind 127.0.0.1) - this server runs arbitrary commands"
            )
        return problems
