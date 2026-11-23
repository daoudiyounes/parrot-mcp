# Security policy

Parrot MCP runs arbitrary shell commands on the machine or container it targets.
That is the feature, not a bug. Read this before exposing it to anything.

## Run it where you mean it

- Point it at a Parrot VM, a container, or a box you own. Never at a shared
  production host.
- The `run_command` tool and every structured wrapper can run anything the
  server's user can run. Run the server as a non-root user where possible, and
  give it a dedicated VM when it needs root (SYN scans, macchanger, anonsurf).

## Guardrails are not a sandbox

The destructive-command check (`parrot_mcp/safety.py`) is a list of regular
expressions. It catches accidents like `rm -rf /`, `dd` to a block device,
`mkfs` and fork bombs. It does not stop a determined command, and it is not a
security boundary. Treat the model as trusted code.

## Network exposure

- HTTP transport has **no TLS**. The bearer token is sent in clear text.
- The server refuses to start on a non-loopback host without
  `PARROT_MCP_AUTH_TOKEN`. Use a long random token.
- Put an HTTPS reverse proxy in front of it for any non-local use.
- `/health` is unauthenticated by design (liveness only).

## Audit log

`--audit-log <file>` (or `PARROT_MCP_AUDIT_LOG`) appends one JSON line per
command: timestamp, target, command text, exit code, duration, error. It does
not record output.

Command text can contain credentials (e.g. `hydra -p <password>`), so the file
is created owner-only (`0600`) and should be stored and shared as sensitive
material.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer
listed in `pyproject.toml`. Please do not open a public issue for anything that
could let an unauthenticated caller run commands.
