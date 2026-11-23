# Testing parrot-mcp locally with a parrotsec Docker container

Two ways to test. **Path A** puts the MCP server *inside* the container (all
Parrot tools preloaded around it) — recommended for a first end-to-end test.
**Path B** runs the server on your host and executes commands inside
containers — this is the `PARROT_MCP_TARGET=docker` mode.

> The project `Dockerfile` / `docker-compose.yml` install `parrot-mcp` from
> PyPI, so they work **after you publish**. Until then, use the steps below.

---

## Path A — MCP server inside a parrotsec container (fastest first test)

The official image already ships most pentest tools, so after these three
commands you can talk to a fully-armed Parrot box through your AI client.

```bash
# 0) get the image (multi-GB, one time)
docker pull parrotsec/security

# 1) run it: map the port, mount the wheel you built (dist/ of this repo)
docker run -d --name parrot-mcp -p 8420:8420 \
  -v "$PWD/dist":/opt/wheels:ro \
  parrotsec/security bash -c '
    apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null
    python3 -m venv /opt/venv
    /opt/venv/bin/pip install -q /opt/wheels/parrot_mcp-1.0.1-py3-none-any.whl
    export PARROT_MCP_AUTH_TOKEN=testtoken
    exec /opt/venv/bin/parrot-mcp --transport http --host 0.0.0.0 --port 8420
  '

# 2) verify it is alive (no auth needed on /health)
curl http://localhost:8420/health
# -> {"status":"ok","version":"1.0.1","target":"local","detected_os":"Parrot OS ...","parrot":true}

# 3) watch the logs if anything looks off
docker logs -f parrot-mcp
```

Notes:

- `parrotsec/security` runs as root, so SYN scans, macchanger, anonsurf etc.
  work out of the box.
- If you did not build the wheel yet: `python -m build` in the repo root
  (or point pip at the source folder instead: `pip install /opt/src`).
- Alternative to the venv (Debian marks system pip externally-managed):
  `pip install --break-system-packages /opt/wheels/*.whl`.

### Connect a client

Claude Code:

```bash
claude mcp add --transport http parrot http://localhost:8420/mcp \
  --header "Authorization: Bearer testtoken"
```

Cline / Cursor / any MCP client (`examples/cline_http.json`,
`examples/cursor_http.json`):

```json
{
  "mcpServers": {
    "parrot": {
      "url": "http://localhost:8420/mcp",
      "headers": { "Authorization": "Bearer testtoken" }
    }
  }
}
```

### First things to ask the assistant

1. `system_info` — should report Parrot OS and the preloaded tools.
2. `check_tools` — OK/MISS list for the whole bundled toolset.
3. `run_command("cat /etc/os-release")` — proves the gateway works.
4. `nmap_scan(target="scanme.nmap.org", scan_type="quick")` — real recon,
   authorized target.
5. `searchsploit_search("openssh 9")` — local Exploit-DB mirror.

---

## Path B — server on the host, commands inside containers

Install on your host machine (`pip install dist/parrot_mcp-1.0.1-py3-none-any.whl`
or `pip install .`), then choose a mode:

**Ephemeral (default)** — every tool call runs in a fresh container, nothing
persists (clean, stateless):

```bash
export PARROT_MCP_TARGET=docker
export PARROT_MCP_DOCKER_IMAGE=parrotsec/security:latest
parrot-mcp --transport stdio        # or --transport http with a token
```

**Persistent** — one named container, state (loot, downloads, sessions)
survives between commands:

```bash
# create the persistent container once
docker run -d --name parrot-mcp parrotsec/security sleep infinity

export PARROT_MCP_TARGET=docker
export PARROT_MCP_DOCKER_CONTAINER=parrot-mcp
parrot-mcp --transport stdio
```

Or do both steps from the chat itself — the assistant can run
`docker_manage(action="pull")`, `docker_manage(action="create",
container="parrot-mcp")` and `set_execution_target(target="docker",
docker_container="parrot-mcp")` for you.

Tips for this mode:

- Docker permissions: your user needs to be in the `docker` group
  (`sudo usermod -aG docker $USER`, re-login) or run the server with sudo.
- Need SYN scans / arp discovery inside the container? Recreate it with
  `--network host --cap-add NET_RAW --cap-add NET_ADMIN` (Linux hosts).
- First ephemeral run pulls the image automatically; pull it manually first
  if you want to see progress.
- On macOS/Windows hosts `--network host` is unavailable; stick to
  `scan_type="tcp_connect"` nmap scans.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `curl /health` connection refused | container not up: `docker ps`, `docker logs parrot-mcp` |
| port 8420 already in use | change mapping: `-p 8421:8420` and update the client URL |
| `pip: externally-managed-environment` | use the venv steps above or `--break-system-packages` |
| `401 unauthorized` in the client | header must be exactly `Authorization: Bearer testtoken` |
| `MISS <tool>` in `check_tools` | expected for a few tools; `run_command("apt install -y <tool>")` |
| first scan hangs minutes | image still pulling — `docker pull parrotsec/security` manually |
| `permission denied ... /var/run/docker.sock` (Path B) | add your user to the docker group or run under sudo |
