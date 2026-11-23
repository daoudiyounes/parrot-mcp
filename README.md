# Parrot MCP

An MCP server that lets an AI assistant run Parrot OS security tools for you.

You point it at a machine — this one, a Parrot VM over SSH, or a Parrot
container — and the assistant can run nmap, gobuster, sqlmap, metasploit and
the rest through a normal MCP connection. It also has `run_command`, so
anything installed on the box is reachable, not just the tools I wrapped.

> Only use this on systems you own or have written permission to test. You are
> responsible for what you run.

## What you get

- **32 tools.** 23 wrappers with sensible defaults (nmap, nikto, gobuster,
  wpscan, sqlmap, searchsploit, hydra, hashcat, john, anonsurf, ...) plus
  `run_command` and a handful of management tools.
- **Three places to run.** Local, SSH to a VM, or a Docker container.
- **A container that remembers.** The Docker target keeps one named container
  alive across commands, so downloaded wordlists, msf sessions and loot are
  still there on the next call. Name a new container when you want a clean box.
- **An audit log.** Optional, one JSON line per command, with the command text,
  exit code and duration. Useful when you have to hand over a record.
- **stdio or HTTP.** Let your client start the server, or run it once and
  connect from anywhere with a bearer token.

## Install

From source for now:

```bash
git clone https://github.com/daoudiyounes/parrot-mcp
cd parrot-mcp
pip install .
```

`pip install parrot-mcp` and `uvx parrot-mcp` will work once the package is on
PyPI — see [PUBLISHING.md](PUBLISHING.md).

## Connect it

Three ways. Pick the one that matches where Parrot lives.

**Docker.** Uses the official `parrotsec/security` image. Nothing to set up; the
container is created on first use and reused:

```bash
claude mcp add parrot -- parrot-mcp --mode docker --container parrot
```

**SSH to a VM.** Use a key, a password, or your ssh-agent:

```bash
claude mcp add parrot -- parrot-mcp --mode ssh --host 192.168.56.101 --user root --key ~/.ssh/parrot
claude mcp add parrot -- parrot-mcp --mode ssh --host 192.168.56.101 --user root --password secret
```

**Local.** When Parrot *is* the machine you're on:

```bash
claude mcp add parrot -- parrot-mcp --mode local
```

Prefer an env var over `--password` if other people use the machine — command
line arguments show up in the process list. Every flag has a `PARROT_MCP_*`
equivalent, and the flag wins when both are set.

For Claude Desktop, Cursor and Cline the JSON is in [`examples/`](examples/).

## Run the server on the network

If you want the server itself running on the Parrot box:

```bash
export PARROT_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
parrot-mcp --mode local --transport http --http-host 0.0.0.0
```

Then point your client at `http://<parrot-ip>:8420/mcp` with
`Authorization: Bearer <token>`.

There is no TLS. Put a reverse proxy in front of it if it leaves your network.
The server won't start on a non-loopback address without a token, but that is a
floor, not a guarantee — read [SECURITY.md](SECURITY.md).

## How it works

```
AI client  ──stdio or HTTP──►  parrot-mcp  ──►  local shell
                                            ├──►  SSH (paramiko)
                                            └──►  docker exec (named container)
```

Everything goes through one executor. The tool response always includes the
exact command, the exit code, stdout and stderr, so you can see what happened
rather than trusting a summary.

## Tools

**Recon**

| Tool | What it does |
|---|---|
| `nmap_scan` | Port and service scans, including vuln scripts |
| `masscan_scan` | Fast port sweeps on large ranges |
| `amass_enum` | Subdomain enumeration (passive by default) |
| `sublist3r_scan` | Subdomains from search engines and passive DNS |
| `whois_lookup` | Registration data |
| `dns_recon` | DNS records, including zone transfer attempts |

**Web**

| Tool | What it does |
|---|---|
| `nikto_scan` | Web server misconfigurations and known issues |
| `whatweb_scan` | Fingerprint CMS, frameworks and servers |
| `gobuster_scan` | Path, DNS and vhost brute force |
| `wpscan_scan` | WordPress enumeration and known vulns |
| `dirsearch_scan` | Path brute force with its own wordlist |
| `ssl_analysis` | TLS versions, ciphers and certificate checks |

**Exploitation**

| Tool | What it does |
|---|---|
| `searchsploit_search` | Search the local Exploit-DB mirror |
| `sqlmap_scan` | SQL injection detection and exploitation |
| `msf_run` | Non-interactive Metasploit console |
| `hydra_attack` | Password brute force against a service |
| `hashcat_crack` | GPU/CPU hash cracking |
| `john_crack` | CPU hash cracking for shadow files and archives |

**Anonymity and OSINT**

| Tool | What it does |
|---|---|
| `anonsurf_control` | Start, stop or change AnonSurf |
| `macchanger_spoof` | Show or spoof a MAC address |
| `proxychains_exec` | Run a command through proxychains |
| `tor_status` | Is Tor up, and is traffic going through it |
| `theharvester_search` | Emails, hosts and subdomains from public sources |

**Management**

| Tool | What it does |
|---|---|
| `run_command` | Any shell command on the target |
| `set_execution_target` | Switch local, SSH or Docker at runtime |
| `get_execution_status` | Current target, timeouts and detected OS |
| `system_info` | Host, resources and which tools are installed |
| `check_tools` | OK or MISS for each bundled tool |
| `docker_manage` | Pull, create, start, stop or remove the container |
| `list_files` | List a directory on the target |
| `get_file_info` | File type, size, SHA256 and MD5 |
| `get_tool_help` | Help output for any installed tool |

Most tools take `extra_args` for flags I didn't wrap. Use `get_tool_help` when
you're not sure what a tool accepts.

## Prompts

Six prompts cover common workflows: `pentest_recon`, `web_assessment`,
`vuln_triage`, `anonymous_recon`, `full_engagement` and `report_findings`.
They show up as slash commands in clients that support prompts.

## Missing tools

The official `parrotsec/security` image ships 11 of the 23 wrapped binaries. The
other 12 — amass, sublist3r, dnsrecon, dirsearch, sslyze, searchsploit, hydra,
anonsurf, macchanger, proxychains4, theHarvester and tor — are not in it.

You don't need a custom image to fix that. The docker target keeps one
container alive, so you install a tool once and it stays:

```text
set_execution_target(target="docker", docker_container="parrot")
run_command(command="apt-get update && apt-get install -y hydra exploitdb")
```

From then on `hydra_attack` and `searchsploit_search` work in that container.
Installing everything up front is one command:

```text
run_command(command="apt-get update && apt-get install -y hydra exploitdb amass sublist3r dnsrecon dirsearch anonsurf anonsurf-cli macchanger proxychains4 theharvester tor seclists && gunzip -f /usr/share/wordlists/rockyou.txt.gz", timeout_seconds=900)
```

`sslyze` has no apt package; `pip install sslyze` inside the container instead.

When a wrapped tool is missing, the error tells you the package to install, e.g.
`note: 'searchsploit' is not installed ... sudo apt install exploitdb`.
`check_tools` lists what is present and what is missing at any time.

## Things it does not do

Worth knowing before you rely on it:

- **No scope enforcement.** Nothing stops a scan at an arbitrary host. Keep
  targets inside your authorization; the tool can't enforce that for you.
- **The guardrail is a regex.** It refuses host-destructive commands like
  `rm -rf /` and `dd` to a disk, across every tool. It is not a sandbox.
- **No long sessions.** It runs a command and returns. Reverse shells, C2
  callbacks and interactive sessions don't fit this model.
- **Anonymity tools need a real host.** AnonSurf and Tor want systemd and
  iptables, which a container doesn't have. Use the SSH target for those.

## Configuration

Every setting is a flag and an env var.

| Flag | Env var | Default | What it does |
|---|---|---|---|
| `--mode` | `PARROT_MCP_TARGET` | `local` | `local`, `ssh` or `docker` |
| `--container` | `PARROT_MCP_DOCKER_CONTAINER` | `parrot-mcp` | Container name; `""` = one per command |
| `--image` | `PARROT_MCP_DOCKER_IMAGE` | `parrotsec/security:latest` | Image for the container |
| `--host` | `PARROT_MCP_SSH_HOST` | `127.0.0.1` | SSH host |
| `--port` | `PARROT_MCP_SSH_PORT` | `22` | SSH port |
| `--user` | `PARROT_MCP_SSH_USER` | `root` | SSH user |
| `--password` | `PARROT_MCP_SSH_PASSWORD` | | SSH password |
| `--key` | `PARROT_MCP_SSH_KEY_PATH` | | Private key path |
| `--key-passphrase` | `PARROT_MCP_SSH_KEY_PASSPHRASE` | | Key passphrase |
| `--timeout` | `PARROT_MCP_TIMEOUT` | `900` | Per-command timeout in seconds |
| `--max-output` | `PARROT_MCP_MAX_OUTPUT` | `30000` | Output clipped per command |
| `--audit-log` | `PARROT_MCP_AUDIT_LOG` | | JSON line per command |
| `--disable-guardrails` | `PARROT_MCP_DISABLE_GUARDRAILS` | off | Run everything unchecked |
| `--transport` | `PARROT_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `--http-host` | `PARROT_MCP_HOST` | `127.0.0.1` | HTTP bind address |
| `--http-port` | `PARROT_MCP_PORT` | `8420` | HTTP port |
| `--http-token` | `PARROT_MCP_AUTH_TOKEN` | | Bearer token for HTTP |

## If something goes wrong

**`MISS hydra` and friends.** The image you're pointed at doesn't have the
tool. Build the bundled image, or `sudo apt install hydra` on the target.

**`rockyou.txt` is missing.** Parrot ships it gzipped:
`sudo gunzip /usr/share/wordlists/rockyou.txt.gz`.

**SYN scans say "operation not permitted".** Either run as root, use
`scan_type="tcp_connect"`, or create the container with
`docker_manage(action="create", extra_args="--cap-add NET_RAW --network host")`.

**Docker daemon not reachable.** Start Docker and make sure your user is in the
`docker` group.

**401 from the HTTP endpoint.** The header must be exactly
`Authorization: Bearer <token>`.

**Output ends with `[output clipped...]`.** That's the 30k limit. Raise
`--max-output` or narrow the query.

**Target looks unreachable.** `get_execution_status` will say so. Check the SSH
host, key or container name.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Licence

MIT. See [LICENSE](LICENSE).
