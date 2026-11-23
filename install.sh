#!/usr/bin/env bash
# parrot-mcp installer for Parrot OS / Debian-based systems.
#
#   ./install.sh            install the parrot-mcp CLI into a private venv
#   ./install.sh --tools    also apt-install the bundled security tools
#
# Parrot OS is Debian-based and marks the system Python as externally
# managed (PEP 668), so we use a dedicated venv in ~/.parrot-mcp/venv and
# expose the `parrot-mcp` command via ~/.local/bin.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
INSTALL_TOOLS=0
[ "${1:-}" = "--tools" ] && INSTALL_TOOLS=1

echo "[*] parrot-mcp installer"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "[!] $PYTHON not found. On Parrot: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

VENV="$HOME/.parrot-mcp/venv"
echo "[*] creating venv at $VENV"
if ! "$PYTHON" -m venv "$VENV" 2>/dev/null; then
    echo "[!] venv module missing - installing python3-venv via apt"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y python3-venv
        "$PYTHON" -m venv "$VENV"
    else
        echo "[!] cannot continue: python3-venv is required"
        exit 1
    fi
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[*] installing parrot-mcp from $SRC_DIR"
"$VENV/bin/pip" install --upgrade pip >/dev/null
"$VENV/bin/pip" install "$SRC_DIR"

mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/parrot-mcp" <<LAUNCHER
#!/usr/bin/env bash
exec "$VENV/bin/parrot-mcp" "\$@"
LAUNCHER
chmod +x "$HOME/.local/bin/parrot-mcp"

if [ "$INSTALL_TOOLS" -eq 1 ]; then
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[!] --tools needs apt-get (Parrot/Debian)"
    else
        echo "[*] installing security tools (missing ones are skipped)"
        TOOLS="nmap masscan nikto gobuster whatweb dirsearch wpscan sslyze hydra sqlmap exploitdb john hashcat amass sublist3r dnsrecon whois dnsutils macchanger tor proxychains4 seclists wordlists curl git"
        sudo apt-get update
        for t in $TOOLS; do
            sudo apt-get install -y --no-install-recommends "$t" >/dev/null 2>&1 \
                || echo "    skip (not in repos): $t"
        done
        echo "[*] unzip the default wordlist if needed: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
    fi
fi

echo
echo "[+] installed. Verify with:"
echo "      parrot-mcp --version"
echo
echo "[*] stdio client config (Claude Desktop / Cline / Cursor):"
echo '      {"mcpServers": {"parrot": {"command": "parrot-mcp", "args": ["--transport", "stdio"]}}}'
echo
echo "[*] long-running HTTP server with auth:"
echo '      export PARROT_MCP_AUTH_TOKEN="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"'
echo '      parrot-mcp --transport http --host 0.0.0.0 --port 8420'
