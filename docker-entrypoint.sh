#!/bin/sh
# Entry point for the parrot-mcp container.
set -e

# `docker run <image> <command>` (the docker execution target) must run that
# command, not the server; only a bare `docker run <image>` starts the server.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Generates a random bearer token when PARROT_MCP_AUTH_TOKEN is empty. It is
# written to a root-only file instead of the log, which is often shipped.
if [ -z "${PARROT_MCP_AUTH_TOKEN:-}" ]; then
    PARROT_MCP_AUTH_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
    export PARROT_MCP_AUTH_TOKEN
    umask 077
    printf '%s\n' "$PARROT_MCP_AUTH_TOKEN" > /root/.parrot-mcp-token
    echo "PARROT_MCP_AUTH_TOKEN was not set - generated one for you." >&2
    echo "Read it with: docker exec <container> cat /root/.parrot-mcp-token" >&2
fi

echo "Parrot MCP | http://0.0.0.0:${PARROT_MCP_PORT:-8420}${PARROT_MCP_PATH:-/mcp} | target=${PARROT_MCP_TARGET:-local}" >&2
exec parrot-mcp --transport http
