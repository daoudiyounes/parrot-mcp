"""Prompt library: ready-made engagement workflows that drive the Parrot MCP tools.

Prompts are exposed through the MCP `prompts` capability - clients surface
them as slash commands / templates so users get a guided methodology instead
of a bare tool list.
"""

from __future__ import annotations

AUTHORIZATION_NOTE = (
    "IMPORTANT: Only run this workflow against systems you own or have explicit, "
    "written permission to test. Record every command you run so the engagement is reproducible."
)


def register(mcp) -> None:
    @mcp.prompt
    def pentest_recon(scope: str) -> str:
        """Guided reconnaissance methodology (passive -> active -> synthesis)."""
        return f"""You are assisting with an authorized reconnaissance engagement against: {scope}

{AUTHORIZATION_NOTE}

Follow these phases with the Parrot MCP tools; summarize findings after each phase:

1. PASSIVE FOOTPRINT (no target contact)
   - whois_lookup(domain) for registration data
   - theharvester_search(domain, sources="bing,duckduckgo,crtsh") for emails/hosts
   - amass_enum(domain, passive=true) for subdomains
2. DNS & HOST DISCOVERY
   - dns_recon(domain) for records and misconfigurations (try scan_type="axfr")
   - nmap_scan(<hosts>, scan_type="ping") to map live hosts, then nmap_scan(host, scan_type="quick")
3. DEEP SCANNING
   - nmap_scan on interesting hosts with scan_type="intense" (or "full" + ports when thorough)
   - masscan_scan for large ranges where nmap is too slow
4. SYNTHESIS
   - For every service+version found: searchsploit_search("<service> <version>")
   - Produce a summary: assets, open ports, software versions, candidate exploits, recommended next steps.

Use run_command for anything the structured tools do not cover."""

    @mcp.prompt
    def web_assessment(target: str) -> str:
        """Structured web application assessment flow."""
        return f"""You are assisting with an authorized web application assessment of: {target}

{AUTHORIZATION_NOTE}

Work through the Parrot MCP tools in this order; explain each step to the user:

1. FINGERPRINT - whatweb_scan(target) to identify server, CMS, frameworks.
2. CONTENT DISCOVERY - gobuster_scan(mode="dir", target, extensions="php,html,txt,bak,asp,aspx,jsp")
   and dirsearch_scan(url) as a second source; gobuster_scan(mode="vhost", ...) for virtual hosts.
3. VULNERABILITY SCANNING - nikto_scan(target) with a generous timeout_seconds (it is slow but thorough).
4. TECHNOLOGY-SPECIFIC CHECKS
   - WordPress found? wpscan_scan(url) (ask the user for a WPVulnDB api_token if available)
   - Login forms / parameters? sqlmap_scan(url) at level=1 risk=1 first, escalate carefully.
   - HTTPS? ssl_analysis(target) for TLS misconfigurations.
5. REPORT - consolidate: findings with severity, evidence (quote tool output), remediation advice.

Escalate intensity only if the user confirms the target is theirs / in scope."""

    @mcp.prompt
    def vuln_triage(host: str) -> str:
        """From open ports to exploitable findings: triage a single host."""
        return f"""You are triaging the host {host} for an authorized engagement.

{AUTHORIZATION_NOTE}

Steps:
1. If you have no scan data yet: nmap_scan("{host}", scan_type="intense") to get services + versions.
2. For EACH service/version pair: searchsploit_search("<software> <version>", json_output=true).
3. For web services: whatweb_scan, then gobuster_scan(mode="dir") for admin panels and backups.
4. Pick the 2-3 most promising exploits. For each, explain: prerequisites, impact, risk of running it.
5. Only attempt exploitation (msf_run, sqlmap_scan, ...) after the user explicitly approves the specific exploit.
6. Document everything: exact commands, outputs, and a severity rating per finding.

Never run destructive payloads without explicit confirmation."""

    @mcp.prompt
    def anonymous_recon(target: str) -> str:
        """OSINT from behind Tor: set up anonymity first, then harvest."""
        return f"""You are performing anonymous OSINT research about: {target}

{AUTHORIZATION_NOTE}

1. ANONYMITY FIRST
   - anonsurf_control(action="status") to see the current state; then anonsurf_control(action="start").
   - tor_status() to confirm the exit IP; optionally macchanger_spoof(interface, mode="random") first.
2. OSINT THROUGH THE TUNNEL
   - proxychains_exec(command="curl -s https://api.ipify.org") to verify the proxy works.
   - theharvester_search(domain) for emails/subdomains, whois_lookup(domain) for registration data,
     amass_enum(domain, passive=true) for subdomains - all passive sources.
3. HYGIENE
   - Keep everything passive (no direct traffic to the target).
   - anonsurf_control(action="stop") when finished; report what was done.

If anonsurf is missing on this machine, fall back to: systemctl start tor, then proxychains_exec for each tool."""

    @mcp.prompt
    def full_engagement(scope: str) -> str:
        """End-to-end pentest methodology: recon -> web -> vulns -> exploitation plan -> report."""
        return f"""You are running a full authorized penetration test against: {scope}

{AUTHORIZATION_NOTE}

Structure the engagement in phases; check in with the user before each escalation:

PHASE 0 - SETUP: system_info() and check_tools() to see what is installed; install gaps with apt via run_command.
PHASE 1 - RECON: run pentest_recon methodology (whois, theHarvester, amass, dnsrecon, nmap).
PHASE 2 - WEB: run web_assessment methodology on every web service found.
PHASE 3 - VULNERABILITY ANALYSIS: searchsploit_search per service/version; rank by exploitability.
PHASE 4 - EXPLOITATION (only with explicit user approval per target/exploit):
   - msf_run for metasploit modules, sqlmap_scan for SQLi, hydra_attack for auth brute-force.
   - Stay within scope; do not pivot to out-of-scope systems.
PHASE 5 - REPORT: findings + severity + evidence + remediation. Use report_findings to draft it.

Keep a running log of every command (the tool output already includes the exact command line)."""

    @mcp.prompt
    def report_findings(target: str) -> str:
        """Turn the gathered tool outputs into a structured pentest report."""
        return f"""Using the tool outputs from this session, draft a penetration test report for {target}.

{AUTHORIZATION_NOTE}

Structure:
1. EXECUTIVE SUMMARY - scope, date, overall risk posture in 3-5 sentences.
2. FINDINGS - one entry per issue: title, severity (Critical/High/Medium/Low/Info),
   affected asset, evidence (paste the relevant tool output), impact, remediation.
3. METHODOLOGY - list the tools/commands used (nmap_scan, gobuster_scan, ...).
4. NEXT STEPS - prioritized remediation plan.

Ask the user for anything missing rather than inventing findings."""
