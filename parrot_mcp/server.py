"""Parrot MCP server entry point: tool registration, stdio and HTTP transports.

HTTP mode serves streamable HTTP at ``/mcp`` protected by a bearer token
(``Authorization: Bearer <PARROT_MCP_AUTH_TOKEN>``) plus an unauthenticated
``/health`` endpoint for monitoring and container healthchecks.
"""

from __future__ import annotations

import argparse
import hmac
import logging
import sys

from fastmcp import FastMCP

from . import __version__
from .state import EXECUTOR, config

log = logging.getLogger("parrot_mcp")

INSTRUCTIONS = """Parrot MCP gives you full control of a Parrot OS machine (or a Parrot Docker
container) for AUTHORIZED security testing, OSINT and CTF work.

How commands run: every tool funnels through an executor with three targets:
- local  : the machine running this server (works best on Parrot OS itself)
- ssh    : a remote Parrot VM (private key, inline key or password auth)
- docker : a named container, created on first use and reused, so state survives
           between commands
Switch targets with set_execution_target; see get_execution_status.

Key tool:
- run_command: execute ANY shell command on the target - the gateway to every tool
  installed on the box. Use it whenever a structured tool does not fit.

Structured tools (curated defaults, prefer them when available):
- recon & network : nmap_scan, masscan_scan, amass_enum, sublist3r_scan, whois_lookup, dns_recon
- web & CMS       : nikto_scan, whatweb_scan, gobuster_scan, wpscan_scan, dirsearch_scan, ssl_analysis
- vulns & exploits: searchsploit_search, sqlmap_scan, msf_run, hydra_attack, hashcat_crack, john_crack
- anonymity/OSINT : anonsurf_control, macchanger_spoof, proxychains_exec, tor_status, theharvester_search
- management      : system_info, check_tools, docker_manage, list_files,
                    get_file_info, get_tool_help

Guidelines:
1. Always confirm the user has authorization for the target.
2. Start passive/light (whois, ping scans, whatweb), escalate only when needed.
3. Check tool availability with check_tools after switching targets; install missing
   tools with `sudo apt install <tool>` via run_command.
4. Long scans need timeout_seconds raised (nikto, amass active, msfconsole).
5. The only built-in guardrail refuses host-destructive commands (rm -rf /, dd to
   block devices, mkfs, fork bombs) in run_command and in every structured tool;
   run_command can override it with confirm_destructive=true. Pentest tooling is
   never filtered.
"""

mcp = FastMCP(name="Parrot MCP", instructions=INSTRUCTIONS, version=__version__)

from .prompts import register as _register_prompts
from .resources import register as _register_resources
from .tools import anon, manage, recon, vuln, web

for _module in (recon, web, vuln, anon, manage):
    _module.register(mcp)
_register_prompts(mcp)
_register_resources(mcp)


def _build_http_app():
    """Assemble the HTTP app: /mcp (bearer-protected) + /health (open)."""
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    class BearerAuthMiddleware(BaseHTTPMiddleware):
        def __init__(self, app, token: str = "", loopback: bool = False):
            super().__init__(app)
            self._token = token
            self._loopback = loopback

        async def dispatch(self, request, call_next):
            if self._loopback:
                host = request.headers.get("host", "").rsplit(":", 1)[0].strip("[]").lower()
                if host not in {"127.0.0.1", "localhost", "::1"}:
                    return JSONResponse(
                        {"error": "forbidden", "detail": "unexpected Host header"},
                        status_code=403,
                    )
            if self._token and request.url.path.startswith(config.path):
                provided = request.headers.get("authorization", "")
                if not hmac.compare_digest(provided, f"Bearer {self._token}"):
                    return JSONResponse(
                        {
                            "error": "unauthorized",
                            "detail": "missing or invalid bearer token",
                        },
                        status_code=401,
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            return await call_next(request)

    loopback = config.host in {"127.0.0.1", "localhost", "::1"}
    middleware = []
    if config.auth_token or loopback:
        middleware.append(
            Middleware(BearerAuthMiddleware, token=config.auth_token, loopback=loopback)
        )
    if not config.auth_token:
        log.warning("PARROT_MCP_AUTH_TOKEN is not set - the /mcp endpoint is UNPROTECTED")

    app = mcp.http_app(path=config.path, middleware=middleware)

    async def health(request):
        os_info = EXECUTOR._last_os or {}
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "target": EXECUTOR.target,
                "detected_os": os_info.get("pretty_name", "unknown"),
                "parrot": os_info.get("is_parrot", False),
            }
        )

    app.router.routes.append(Route("/health", health, methods=["GET"]))
    return app


def _serve_http() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit(
            "uvicorn is required for HTTP transport: pip install 'parrot-mcp[http]' or pip install uvicorn"
        ) from exc
    app = _build_http_app()
    print(
        f"Parrot MCP v{__version__} | target={EXECUTOR.target} | http://{config.host}:{config.port}{config.path}",
        file=sys.stderr,
    )
    print(
        "auth: bearer token required (PARROT_MCP_AUTH_TOKEN)"
        if config.auth_token
        else "auth: WARNING - no PARROT_MCP_AUTH_TOKEN set, /mcp is open",
        file=sys.stderr,
    )
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


def build_parser() -> argparse.ArgumentParser:
    """CLI flags. Every flag overrides the matching PARROT_MCP_* env var."""
    p = argparse.ArgumentParser(
        prog="parrot-mcp",
        description="Parrot OS MCP server - full-control security tooling over MCP (local / SSH / Docker).",
        epilog=(
            "examples:\n"
            "  parrot-mcp --mode docker --container parrot\n"
            "  parrot-mcp --mode ssh --host 192.168.56.101 --user root --key ~/.ssh/parrot\n"
            "  parrot-mcp --mode ssh --host 10.0.0.5 --user root --password secret\n"
            "  parrot-mcp --mode local\n"
            "  parrot-mcp --mode local --transport http --http-host 0.0.0.0 --http-token SECRET\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"parrot-mcp {__version__}")

    p.add_argument(
        "--mode",
        "--target",
        dest="mode",
        choices=["local", "ssh", "docker"],
        default=config.target,
        help="where commands run: local, ssh (VM) or docker (container). Default: local",
    )

    p.add_argument(
        "--container",
        default=config.docker_container,
        help="docker container name; created on first use and reused. '' = one per command",
    )
    p.add_argument(
        "--image",
        "--docker-image",
        dest="image",
        default=config.docker_image,
        help="docker image (default parrotsec/security:latest)",
    )

    p.add_argument("--host", default=config.ssh_host, help="SSH host of the Parrot VM")
    p.add_argument("--port", type=int, default=config.ssh_port, help="SSH port (default 22)")
    p.add_argument("--user", default=config.ssh_user, help="SSH user (default root)")
    p.add_argument("--password", default=config.ssh_password, help="SSH password")
    p.add_argument(
        "--key",
        dest="key_path",
        default=config.ssh_key_path,
        help="SSH private key path",
    )
    p.add_argument("--key-passphrase", default=config.ssh_key_passphrase, help="SSH key passphrase")

    p.add_argument(
        "--timeout",
        type=int,
        default=config.timeout,
        help="default per-command timeout (s)",
    )
    p.add_argument(
        "--max-output",
        type=int,
        default=config.max_output,
        help="stdout/stderr clip (chars)",
    )
    p.add_argument(
        "--audit-log",
        default=config.audit_log,
        help="append one JSON line per command (no output) to this file",
    )
    p.add_argument(
        "--disable-guardrails",
        action="store_true",
        default=config.disable_guardrails,
        help="run every command with no destructiveness check",
    )

    p.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=config.transport,
        help="stdio (client-spawned) or http (long-running server)",
    )
    p.add_argument("--http-host", default=config.host, help="HTTP bind host (default 127.0.0.1)")
    p.add_argument(
        "--http-port",
        type=int,
        default=config.port,
        help="HTTP bind port (default 8420)",
    )
    p.add_argument("--http-path", dest="path", default=config.path, help="MCP endpoint path")
    p.add_argument(
        "--http-token",
        "--auth-token",
        dest="http_token",
        default=config.auth_token,
        help="bearer token required for HTTP",
    )
    return p


def _apply_args(args: argparse.Namespace) -> None:
    """Copy parsed flags onto the shared config and the executor (flag > env > default)."""
    config.transport = args.transport
    config.host = args.http_host
    config.port = args.http_port
    config.path = args.path
    config.auth_token = args.http_token
    config.timeout = args.timeout
    config.max_output = args.max_output
    config.audit_log = args.audit_log
    config.disable_guardrails = args.disable_guardrails

    for executor in (EXECUTOR,):
        executor.target = args.mode
        executor.timeout = args.timeout
        executor.max_output = args.max_output
        executor.audit_log = args.audit_log
        executor.disable_guardrails = args.disable_guardrails
        executor.docker_container = args.container
        executor.docker_image = args.image
        executor.ssh_host = args.host
        executor.ssh_port = args.port
        executor.ssh_user = args.user
        executor.ssh_password = args.password
        executor.ssh_key_path = args.key_path
        executor.ssh_key_passphrase = args.key_passphrase
    config.target = args.mode
    config.docker_container = args.container
    config.docker_image = args.image
    config.ssh_host = args.host
    config.ssh_port = args.port
    config.ssh_user = args.user
    config.ssh_password = args.password
    config.ssh_key_path = args.key_path
    config.ssh_key_passphrase = args.key_passphrase


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    _apply_args(args)

    problems = config.validate()
    if problems:
        for problem in problems:
            print(f"parrot-mcp: configuration problem: {problem}", file=sys.stderr)
        sys.exit(2)

    if config.target == "local" and sys.platform == "win32":
        print(
            "parrot-mcp: mode=local on Windows - the structured tools expect a POSIX shell. "
            "Use --mode ssh (Parrot VM) or --mode docker (parrotsec/security) instead.",
            file=sys.stderr,
        )

    logging.basicConfig(
        level=getattr(
            logging,
            __import__("os").environ.get("PARROT_MCP_LOG_LEVEL", "WARNING").upper(),
            logging.WARNING,
        ),
        stream=sys.stderr,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if config.transport == "http":
        _serve_http()
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
