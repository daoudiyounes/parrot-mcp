"""Recon & network tools: nmap, masscan, amass, sublist3r, whois, dnsrecon."""

from __future__ import annotations

import shlex

from . import run_shell

NMAP_SCAN_TYPES = {
    "default": "-sV",
    "syn": "-sS -sV",
    "tcp_connect": "-sT -sV",
    "udp": "-sU -sV",
    "intense": "-T4 -A -v",
    "quick": "-T4 -F",
    "ping": "-sn",
    "arp": "-PR -sn",
    "vuln": "-sV --script vuln",
    "full": "-T4 -p- -sV",
}


def build_nmap_command(target: str, ports: str | None, scan_type: str, extra_args: str) -> str:
    scan = (scan_type or "default").strip().lower()
    if scan not in NMAP_SCAN_TYPES:
        raise ValueError(
            f"unknown scan_type {scan_type!r}; choose from: {', '.join(NMAP_SCAN_TYPES)}"
        )
    parts = ["nmap", NMAP_SCAN_TYPES[scan]]
    if ports:
        parts.append(f"-p {shlex.quote(ports.strip())}")
    if extra_args:
        parts.append(extra_args.strip())
    parts.append(shlex.quote(target))
    return " ".join(p for p in parts if p)


def build_masscan_command(target: str, ports: str, rate: int, extra_args: str) -> str:
    if not ports:
        raise ValueError("masscan requires a port spec (e.g. '80,443' or '1-65535')")
    parts = [
        "masscan",
        shlex.quote(target),
        f"-p{shlex.quote(ports.strip())}",
        f"--rate={int(rate)}",
    ]
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def build_amass_command(domain: str, passive: bool, extra_args: str) -> str:
    parts = ["amass", "enum", "-d", shlex.quote(domain)]
    if passive:
        parts.append("-passive")
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def build_dnsrecon_command(domain: str, scan_type: str, extra_args: str) -> str:
    parts = [
        "dnsrecon",
        "-d",
        shlex.quote(domain),
        "-t",
        shlex.quote((scan_type or "std").strip()),
    ]
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def register(mcp) -> None:
    @mcp.tool
    async def nmap_scan(
        target: str,
        ports: str | None = None,
        scan_type: str = "default",
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Scan hosts and networks with Nmap.

        Args:
            target: IP, hostname or CIDR range, e.g. "10.0.0.5", "scanme.nmap.org", "10.0.0.0/24".
            ports: Port spec, e.g. "80,443" or "1-1000". Ignored by ping/arp discovery scans.
            scan_type: one of: default (service versions), syn (fast, needs root), tcp_connect,
                udp (needs root), intense (-T4 -A -v), quick (top 100 ports), ping (host discovery),
                arp (local LAN discovery), vuln (nmap vuln scripts), full (all 65535 ports, slow).
            extra_args: extra raw nmap flags, e.g. "--open --script http-title".
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_nmap_command(target, ports, scan_type, extra_args), timeout_seconds
        )

    @mcp.tool
    async def masscan_scan(
        target: str,
        ports: str,
        rate: int = 1000,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Ultra-fast port scan with Masscan - useful for large ranges where nmap is too slow.

        Requires root (run the server as root). Keep --rate modest (1000-5000) unless you
        own the network; high rates can break fragile devices and attract attention.

        Args:
            target: IP or CIDR range, e.g. "10.0.0.0/24".
            ports: Port spec, e.g. "80,443" or "1-65535".
            rate: packets per second. Start low, increase gradually.
            extra_args: extra raw masscan flags.
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_masscan_command(target, ports, rate, extra_args), timeout_seconds
        )

    @mcp.tool
    async def amass_enum(
        domain: str,
        passive: bool = True,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Enumerate subdomains of a domain with OWASP Amass.

        Args:
            domain: base domain, e.g. "example.com".
            passive: True = only certificate-transparency and passive sources (no direct
                traffic to the target, safe and quiet). False = active enumeration (more
                results, more visible). Active mode can take a very long time - raise
                timeout_seconds.
            extra_args: extra raw amass flags.
            timeout_seconds: override the per-command timeout (passive runs are long).
        """
        return await run_shell(build_amass_command(domain, passive, extra_args), timeout_seconds)

    @mcp.tool
    async def sublist3r_scan(
        domain: str,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Enumerate subdomains with Sublist3r (search engines + passive DNS sources).

        Args:
            domain: base domain, e.g. "example.com".
            extra_args: extra raw sublist3r flags, e.g. "-v".
            timeout_seconds: override the per-command timeout.
        """
        command = f"sublist3r -d {shlex.quote(domain)}"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)

    @mcp.tool
    async def whois_lookup(
        domain: str,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """WHOIS lookup: registrar, nameservers, creation/expiry dates, abuse contacts.

        Args:
            domain: domain name, e.g. "example.com".
            extra_args: extra raw whois flags.
            timeout_seconds: override the per-command timeout.
        """
        command = f"whois {shlex.quote(domain)}"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)

    @mcp.tool
    async def dns_recon(
        domain: str,
        scan_type: str = "std",
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Enumerate DNS records with dnsrecon (A/AAAA/MX/NS/SOA/TXT and more).

        Args:
            domain: domain name, e.g. "example.com".
            scan_type: "std" (common records), "axfr" (zone transfer attempt),
                "brt" (brute-force subdomains, needs -f wordlist via extra_args),
                "srv", "any".
            extra_args: extra raw dnsrecon flags.
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_dnsrecon_command(domain, scan_type, extra_args), timeout_seconds
        )
