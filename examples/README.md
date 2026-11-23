# Example client configurations

Copy the JSON that matches your client, replace the placeholders
(`<token>`, IP, paths), and paste it into the client's MCP settings.

| File | Transport | Scenario |
|---|---|---|
| `claude_desktop_stdio.json` | stdio | Claude Desktop launches parrot-mcp locally; commands run on that machine (`PARROT_MCP_TARGET=local`) |
| `claude_desktop_ssh_vm.json` | stdio | Claude Desktop launches parrot-mcp, which drives a **remote Parrot VM over SSH** with a private key |
| `cline_http.json` | streamable HTTP | Cline (VS Code) connects to a long-running parrot-mcp HTTP server with bearer auth |
| `cursor_http.json` | HTTP | Cursor connects to the same HTTP server |

Password SSH auth: replace the key entries with `"PARROT_MCP_SSH_PASSWORD": "..."`.
Generate a token: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.

Claude Desktop config location: `claude_desktop_config.json` (Settings → Developer → Edit Config).
Cursor config location: `~/.cursor/mcp.json`.
Cline: MCP Servers → Remote/Local, paste accordingly.
