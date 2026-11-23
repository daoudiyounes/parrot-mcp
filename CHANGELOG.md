# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-23

### Fixed
- `Dockerfile` could not build: it ran `pip install parrot-mcp` before the
  package was published to PyPI and never copied the source. It now copies the
  repo, installs it from source, adds the missing tools (hydra, exploitdb,
  amass, sublist3r, dnsrecon, dirsearch, anonsurf, macchanger, tor,
  proxychains4, theHarvester, seclists) and unzips `rockyou.txt`.
- The image put its venv first on `PATH`, so system tools that shell out to
  `python3` (dirsearch, ...) ran on the venv interpreter and crashed on
  `pkg_resources`. The venv is now last on `PATH`, and `python3-setuptools` is
  installed for the dist-packages interpreter.
- Parrot 7.2 ships the AnonSurf CLI as a separate `anonsurf-cli` package; the
  image now installs it (the `anonsurf` package alone has no `anonsurf` binary).
- `check_tools` no longer probes for `docker` inside the target, where the
  Docker CLI never exists (it is the transport, not a tool running on the target).
- The image's entrypoint ignored its arguments, so using the built image as a
  `docker` execution target just started the server instead of running commands.
  A bare `docker run <image>` still starts the server; any command is executed.

### Security
- HTTP on a non-loopback host now refuses to start without
  `PARROT_MCP_AUTH_TOKEN` (it runs arbitrary commands, so an open endpoint is a
  remote-code-execution hole).
- The container no longer prints its generated bearer token to the log; it is
  written to `/root/.parrot-mcp-token` (0600) instead.
- Documented that HTTP has no TLS and that the command guardrail is a regex,
  not a sandbox. Added `SECURITY.md`.

### Added
- `get_tool_help` now rejects anything that is not a plain binary name, so a
  value copied from a report cannot inject a second command. It tries `--help`,
  then `-h`, then the bare tool, and caps help calls at 300s.
- When a wrapped tool is missing, the error names the apt package to install
  (with aliases for searchsploit, theHarvester and anonsurf).
- CLI flags for the whole setup, so a client config is one line:
  `parrot-mcp --mode docker --container parrot`,
  `parrot-mcp --mode ssh --host IP --user root --key ~/.ssh/parrot`,
  `parrot-mcp --mode local`. Also `--image`, `--port`, `--password`,
  `--key-passphrase`, `--timeout`, `--max-output`, `--audit-log`,
  `--disable-guardrails`, `--http-host`, `--http-port`, `--http-token`.
  `--target` remains an alias of `--mode`; HTTP bind flags moved to `--http-*`
  so `--host`/`--port` mean the SSH endpoint.
- `.github/workflows/ci.yml`: tests on Python 3.10-3.13, a clean install check,
  and an image job that runs every bundled tool and hits `/health`.
- Optional audit log (`--audit-log` / `PARROT_MCP_AUDIT_LOG`): one JSON line
  per command with timestamp, target, command text, exit code, duration and
  error. Output is deliberately not recorded.
- `list_files`, `get_file_info` and `get_tool_help` tools: browse the target,
  hash a file, and read the usage of any installed tool.
- DNS-rebinding protection: a loopback HTTP bind rejects requests whose `Host`
  header is not a loopback name.
- README "Three ways to connect" section covering local, SSH and docker/HTTP.

### Changed
- The docker target is now a named, persistent container by default: it is
  created on first use (`docker_manage action='create'` is no longer required)
  and reused, so files, msf sessions and loot survive between commands. Point
  at a new name to start fresh; set the name to `""` for one container per
  command (the old default).
- The destructive-command guardrail only covered `run_command`; every
  structured tool now funnels through the same check, and all tool inputs
  (targets, domains, URLs, ports, scan types, extensions) are shell-quoted.
- `docker_manage` failed when the active target was `docker` (no docker CLI
  inside the container); it now always talks to the host daemon.
- `docker_manage(extra_args=...)` was pasted into a host shell unquoted, so a
  crafted value could run commands on the analyst's machine. It is now split
  into arguments and each one quoted.
- `install.sh` installed `parrot-mcp` from PyPI, which does not exist yet; it
  now installs from the checkout. `install.ps1` no longer prefers a stale wheel.
- `proxychains_exec` fell back to `proxychains` when `proxychains4` is absent
  (the name Parrot/Debian actually ship).
- `check_tools` / `system_info` / `parrot://tools` used a POSIX `command -v`
  probe that broke on a Windows local target; they now use `Executor.locate`,
  which also raises "target unreachable" instead of reporting every tool missing
  when the SSH host or container cannot be reached.
- Timed-out local commands on Windows now kill the process tree
  (`taskkill /T`), matching the POSIX `killpg` behaviour.
- HTTP bearer token comparison uses `hmac.compare_digest`.

### Changed
- `set_execution_target(target="docker")` warns when it lands in ephemeral
  mode (no state persists between commands).
- Starting with `target=local` on Windows prints a warning pointing at the
  `ssh` / `docker` targets.

## [1.0.1] - 2026-11-22

### Fixed
- Windows host support: `_run_local` no longer uses the POSIX-only
  `start_new_session` / `os.killpg` on Windows (timed-out local commands are
  killed with `proc.kill()` instead). The `ssh` and `docker` targets were
  already Windows-compatible (argv-list subprocess, UTF-8 decode with
  error replacement).

### Added
- `install.ps1` PowerShell installer, Claude Desktop example config for
  Windows (`examples/claude_desktop_windows.json`) and a step-by-step
  Windows hosting guide (`WINDOWS.md`).

## [1.0.0] - 2026-11-22

### Added
- MCP server exposing Parrot OS security tooling to AI assistants
  (Model Context Protocol, built on FastMCP).
- Three execution targets: `local`, `ssh` (private key, inline key, or
  password auth, via paramiko/SFTP) and `docker` (ephemeral
  `parrotsec/security` containers or a persistent named container).
- Gateway tool `run_command` for unrestricted access to every tool
  installed on the target machine.
- ~24 structured tool wrappers across four categories: recon & network
  (nmap, masscan, amass, sublist3r, whois, dnsrecon), web & CMS (nikto,
  whatweb, gobuster, wpscan, dirsearch, sslyze), vulns & exploits
  (searchsploit, sqlmap, msfconsole, hydra, hashcat, john), anonymity &
  OSINT (anonsurf, macchanger, proxychains, tor status, theHarvester).
- Management tools: `set_execution_target`, `get_execution_status`,
  `system_info`, `check_tools`, `docker_manage`, `ssh_file_transfer`.
- Prompt library (pentest recon, web assessment, vuln triage, anonymous
  recon, full engagement, report writing) and resources
  (`parrot://status`, `parrot://tools`).
- Streamable HTTP transport with bearer-token auth + `/health` endpoint;
  stdio transport for local clients.
- OS detection with graceful fallback when the target is not Parrot OS.
- Soft guardrails (host-destructive commands need explicit confirmation;
  fully disable-able) with full-control execution otherwise.
- Dockerfile (based on `parrotsec/security`), docker-compose deployment,
  `install.sh`, pytest suite, full README.
