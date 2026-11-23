# Hosting parrot-mcp on a Windows host

The Windows host runs the MCP server; every pentest command executes inside a
parrotsec container managed by Docker Desktop. This is the supported setup —
the server's `local` target is only useful as a smoke test on Windows (see
"Windows-specific notes" below).

What works on Windows:

- **docker target** (recommended): ephemeral or persistent `parrotsec/security`
  containers — full Parrot toolset, root inside the container.
- **HTTP transport** for Claude Code / Cline / Cursor, and **stdio transport**
  for Claude Desktop.
- **ssh target** if you also have a Parrot VM elsewhere (unchanged from README).

## 1. Prerequisites

1. **Python 3.10+** from <https://www.python.org/downloads/> — tick
   *"Add python.exe to PATH"* during setup. Verify in PowerShell: `py -3 --version`.
2. **Docker Desktop** with the default WSL 2 backend, installed *and running*
   (whale icon in the system tray). If `docker ps` says "command not found",
   open a **new** terminal after installing, or add Docker Desktop to PATH.
3. Pull the image once (multi-GB):

```powershell
docker pull parrotsec/security
```

## 2. Install the server

```powershell
cd C:\Users\you\parrot-mcp        # the project folder
.\install.ps1
```

If Windows blocks the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Manual alternative (same result):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\pip install --upgrade pip
.\.venv\Scripts\pip install dist\parrot_mcp-1.0.1-py3-none-any.whl
.\.venv\Scripts\parrot-mcp.exe --version
# -> parrot-mcp 1.0.1
```

## 3A. Claude Desktop (stdio — simplest, no terminal needed)

Claude Desktop launches the server itself; the config carries the env vars.

1. Copy the folder's `examples\claude_desktop_windows.json` into
   `%APPDATA%\Claude\claude_desktop_config.json` (press Win+R, type
   `%APPDATA%\Claude`), then fix the `command` path to **your** install
   folder, e.g. `C:\\Users\\you\\parrot-mcp\\.venv\\Scripts\\parrot-mcp.exe`.
2. Fully restart Claude Desktop (tray icon → Quit, then reopen).
3. Ask the assistant to `run system_info` — it should report
   `Parrot OS ... (docker)`.

To use a **persistent** container with Claude Desktop, add
`"PARROT_MCP_DOCKER_CONTAINER": "parrot-mcp"` to the `env` block and create
the container once (step 3C).

## 3B. HTTP server (Claude Code / Cline / Cursor)

```powershell
cd C:\Users\you\parrot-mcp
$env:PARROT_MCP_TARGET = "docker"
$env:PARROT_MCP_DOCKER_IMAGE = "parrotsec/security:latest"
$env:PARROT_MCP_AUTH_TOKEN = "testtoken"
.\.venv\Scripts\parrot-mcp.exe --transport http --host 127.0.0.1 --port 8420
```

Windows Firewall will prompt once — **Allow** (private networks). Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8420/health
# status ok, version 1.0.1, target docker
```

Claude Code (in a second terminal):

```powershell
claude mcp add --transport http parrot http://127.0.0.1:8420/mcp --header "Authorization: Bearer testtoken"
```

Cline / Cursor: use `examples\cline_http.json` / `examples\cursor_http.json`
as-is — `url` + `Authorization: Bearer testtoken` header, no Windows changes.

## 3C. Persistent container (state survives between commands)

```powershell
docker run -d --name parrot-mcp parrotsec/security sleep infinity

# then either set this env var before starting the server
$env:PARROT_MCP_DOCKER_CONTAINER = "parrot-mcp"

# or switch targets from the chat itself:
#   set_execution_target(target="docker", docker_container="parrot-mcp")
```

Loot and downloads stay inside the container between commands. Copy results
out to Windows with:

```powershell
docker cp parrot-mcp:/tmp/loot C:\Users\you\Desktop\loot
```

## 4. Windows-specific notes

| Topic | Note |
|---|---|
| nmap scans | `--network host` is unavailable on Docker Desktop — use `scan_type="tcp_connect"` (SYN scans inside containers need Linux + host networking) |
| docker permissions | nothing to configure — Docker Desktop handles it (no `docker` group like Linux) |
| WSL 2 errors | `wsl --update`, then check virtualization is enabled in BIOS/UEFI |
| JSON client configs | paths need double backslashes: `"C:\\Users\\you\\..."` |
| first command "hangs" | ephemeral mode pulls the image on first use if not pulled yet — you did that in step 1 |
| port 8420 busy | change it: `--port 8421` (and the client URL) |
| `local` target on Windows | runs cmd.exe/PowerShell — good for a smoke test (`run_command("whoami")`), but the pentest toolset only exists inside the Parrot containers |

## 5. Smoke-test checklist

1. `docker ps` — Docker Desktop is alive.
2. `/health` returns JSON (HTTP mode) or Claude Desktop shows the parrot
   server connected (stdio mode).
3. In chat: `system_info` → `Parrot OS ... (docker)`.
4. `check_tools` → mostly OK.
5. `nmap_scan(target="scanme.nmap.org", scan_type="tcp_connect")` → live results
   from inside the container.
