"""Web & CMS auditing tools: nikto, whatweb, gobuster, wpscan, dirsearch, sslyze."""

from __future__ import annotations

import shlex

from . import run_shell

GOBUSTER_MODES = {"dir", "dns", "vhost", "fuzz"}

DEFAULT_DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_DNS_WORDLIST = "/usr/share/seclists/DNS/subdomains-top1million-5000.txt"


def build_gobuster_command(
    mode: str,
    target: str,
    wordlist: str | None,
    extensions: str | None,
    extra_args: str,
) -> str:
    mode = (mode or "dir").strip().lower()
    if mode not in GOBUSTER_MODES:
        raise ValueError(f"unknown mode {mode!r}; choose from: {', '.join(GOBUSTER_MODES)}")
    if mode == "dir":
        parts = [
            "gobuster",
            "dir",
            "-u",
            shlex.quote(target),
            "-w",
            shlex.quote(wordlist or DEFAULT_DIR_WORDLIST),
        ]
        if extensions:
            parts += ["-x", shlex.quote(extensions.strip())]
    elif mode == "dns":
        parts = [
            "gobuster",
            "dns",
            "-d",
            shlex.quote(target),
            "-w",
            shlex.quote(wordlist or DEFAULT_DNS_WORDLIST),
        ]
    elif mode == "vhost":
        parts = [
            "gobuster",
            "vhost",
            "-u",
            shlex.quote(target),
            "-w",
            shlex.quote(wordlist or DEFAULT_DIR_WORDLIST),
        ]
    else:
        parts = [
            "gobuster",
            "fuzz",
            "-u",
            shlex.quote(target),
            "-w",
            shlex.quote(wordlist or DEFAULT_DIR_WORDLIST),
        ]
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def build_nikto_command(target: str, port: int | None, use_ssl: bool, extra_args: str) -> str:
    parts = ["nikto", "-h", shlex.quote(target)]
    if port:
        parts += ["-p", str(port)]
    if use_ssl:
        parts.append("-ssl")
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def register(mcp) -> None:
    @mcp.tool
    async def nikto_scan(
        target: str,
        port: int | None = None,
        use_ssl: bool = False,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Web server vulnerability scan with Nikto (dangerous defaults, outdated software, misc issues).

        Nikto is noisy and slow (often 10-30+ min per host) - raise timeout_seconds and
        prefer it after faster recon (whatweb/gobuster) has confirmed a web service.

        Args:
            target: host or URL, e.g. "10.0.0.5" or "http://target.local".
            port: target port (default 80, or 443 when use_ssl is set).
            use_ssl: force TLS mode (-ssl).
            extra_args: extra raw nikto flags, e.g. "-Tuning x 6".
            timeout_seconds: override the per-command timeout (nikto needs a big one).
        """
        return await run_shell(
            build_nikto_command(target, port, use_ssl, extra_args), timeout_seconds
        )

    @mcp.tool
    async def whatweb_scan(
        target: str,
        aggression: int = 1,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Fingerprint web technologies with WhatWeb: CMS, frameworks, servers.

        Args:
            target: URL or host, e.g. "http://10.0.0.5".
            aggression: 1 = stealthy single request (default), 3 = light guesswork,
                4/5 = more requests, may be considered aggressive by the target.
            extra_args: extra raw whatweb flags.
            timeout_seconds: override the per-command timeout.
        """
        command = f"whatweb -a {int(aggression)} {shlex.quote(target)}"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)

    @mcp.tool
    async def gobuster_scan(
        mode: str,
        target: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Brute-force URLs/DNS/vhosts with Gobuster - find hidden paths, admin panels, backups.

        Args:
            mode: "dir" (URL paths), "dns" (subdomains), "vhost" (virtual hosts), "fuzz".
            target: for dir/vhost/fuzz a base URL (e.g. "http://10.0.0.5"); for dns a domain.
            wordlist: path to wordlist. Defaults: dir/vhost -> /usr/share/wordlists/dirb/common.txt,
                dns -> /usr/share/seclists/DNS/subdomains-top1million-5000.txt. On Parrot also see
                /usr/share/seclists/Discovery/Web-Content/ (install the seclists package if missing).
            extensions: file extensions for dir mode, e.g. "php,html,txt,bak".
            extra_args: extra raw gobuster flags, e.g. "-t 30 --no-error".
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_gobuster_command(mode, target, wordlist, extensions, extra_args),
            timeout_seconds,
        )

    @mcp.tool
    async def wpscan_scan(
        url: str,
        api_token: str | None = None,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Audit a WordPress site with WPScan (core/theme/plugin versions, users, known vulns).

        Args:
            url: base URL of the WordPress site, e.g. "http://10.0.0.5/blog".
            api_token: WPVulnDB API token (free at wpscan.com) - needed to see vulnerability data.
            extra_args: extra raw wpscan flags, e.g. "--enumerate u --passwords rockyou.txt".
            timeout_seconds: override the per-command timeout.
        """
        parts = ["wpscan", "--url", shlex.quote(url)]
        if api_token:
            parts += ["--api-token", shlex.quote(api_token)]
        parts += ["--enumerate", "vp,vt,u"]
        if extra_args:
            parts.append(extra_args.strip())
        return await run_shell(" ".join(p for p in parts if p), timeout_seconds)

    @mcp.tool
    async def dirsearch_scan(
        url: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        recursive: bool = False,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Brute-force web paths with dirsearch (alternative to gobuster, built-in wordlist).

        Args:
            url: base URL, e.g. "http://10.0.0.5".
            wordlist: custom wordlist path (dirsearch ships a default db).
            extensions: comma-separated extensions, e.g. "php,asp,html".
            recursive: recurse into discovered directories (slower).
            extra_args: extra raw dirsearch flags, e.g. "-t 30 -i 200".
            timeout_seconds: override the per-command timeout.
        """
        parts = ["dirsearch", "-u", shlex.quote(url)]
        if wordlist:
            parts += ["-w", shlex.quote(wordlist)]
        if extensions:
            parts += ["-e", extensions]
        if recursive:
            parts.append("-r")
        if extra_args:
            parts.append(extra_args.strip())
        return await run_shell(" ".join(p for p in parts if p), timeout_seconds)

    @mcp.tool
    async def ssl_analysis(
        target: str,
        port: int = 443,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Analyze TLS/SSL configuration with sslyze (protocols, ciphers, certs, vulnerabilities).

        Args:
            target: hostname or IP.
            port: TLS port (default 443).
            extra_args: extra raw sslyze flags, e.g. "--certinfo".
            timeout_seconds: override the per-command timeout.
        """
        command = f"sslyze {shlex.quote(target)}:{int(port)}"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)
