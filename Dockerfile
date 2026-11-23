# Parrot MCP - server + Parrot OS pentest tooling in one container.
#
# Build:  docker build -t parrot-mcp .
# Run:    docker run -d --name parrot-mcp -p 8420:8420 \
#           -e PARROT_MCP_AUTH_TOKEN=<long-random-string> parrot-mcp
#
# The official parrotsec/security image ships a partial toolset; the loop below
# adds every tool the structured MCP tools wrap. Package names were checked
# against the Parrot 7.x repos; a name that disappears is skipped, not fatal.
FROM parrotsec/security:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    for p in python3 python3-venv python3-pip python3-setuptools ca-certificates curl \
             nmap masscan nikto gobuster whatweb wpscan dirsearch sqlmap exploitdb \
             hydra hashcat john amass sublist3r dnsrecon whois dnsutils \
             macchanger tor proxychains4 anonsurf anonsurf-cli theharvester \
             seclists wordlists git openssh-client file; do \
        if ! apt-get install -y --no-install-recommends "$p" >/tmp/apt.log 2>&1; then \
            echo "[build] SKIPPED $p:"; tail -3 /tmp/apt.log; \
        fi; \
    done && \
    rm -rf /var/lib/apt/lists/*

# Parrot ships rockyou gzipped; hydra/hashcat defaults expect the plain file.
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip -f /usr/share/wordlists/rockyou.txt.gz; \
    fi

# parrot-mcp itself in a private venv (avoids PEP 668 externally-managed env).
# sslyze has no apt package in Parrot, so it comes from pip.
COPY . /opt/parrot-mcp
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir /opt/parrot-mcp sslyze

# venv goes LAST on PATH: system tools (dirsearch, dnsrecon, ...) shell out to
# `python3` and need the dist-packages interpreter, not the venv one.
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/venv/bin"

# Default to an authenticated HTTP server reachable from outside the container.
# PARROT_MCP_AUTH_TOKEN is intentionally not set here: the entrypoint generates
# one on startup when it is unset, and secrets do not belong in ENV.
ENV PARROT_MCP_TRANSPORT=http \
    PARROT_MCP_HOST=0.0.0.0 \
    PARROT_MCP_PORT=8420 \
    PARROT_MCP_PATH=/mcp

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:8420/health || exit 1

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
