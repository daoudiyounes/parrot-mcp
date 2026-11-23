"""Soft guardrails for ``run_command``.

Parrot MCP runs in *full control* mode: every security tool and every shell
command is allowed, with no filtering of pentest tooling. The only built-in
protection is against commands that would destroy the machine the executor
runs on (your Parrot box / VM / container) - those require an explicit
``confirm_destructive=True`` argument, and the whole layer can be switched
off with ``PARROT_MCP_DISABLE_GUARDRAILS=1``.
"""

from __future__ import annotations

import re

DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\brm\s+(?:-{1,2}[\w-]+\s+)*-{1,2}\w*[rf]\w*\s+"
            r"(?:/{1,2}(?:\s|$)|/\*|~(?:\s|$)|\$HOME\b|/(?:etc|usr|var|boot|bin|sbin|lib|opt|home|root)\b)"
        ),
        "recursive delete of a system path",
    ),
    (
        re.compile(r"\bdd\b[^;|\n]*\bof=/dev/(?:sd|nvme|vd|hd|mmcblk|mapper/)"),
        "raw write to a block device with dd",
    ),
    (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b"), "filesystem creation (mkfs)"),
    (re.compile(r"\bshred\b[^;|\n]*\s/dev/(?:sd|nvme|vd|hd)"), "shred a block device"),
    (
        re.compile(r">\s*/dev/(?:sd|nvme|vd|hd)[a-z0-9]"),
        "redirect output onto a block device",
    ),
    (
        re.compile(r"\bfind\s+/\s+[^;|\n]*-delete"),
        "recursive delete with find / -delete",
    ),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\bchmod\b[^;|\n]*\s-R[^;|\n]*\s0{3}\s+/(?:\s|$)"), "chmod -R 000 /"),
]


def check_command(command: str, enabled: bool = True) -> list[str]:
    """Return the reasons a command looks host-destructive (empty if safe/disabled).

    ``enabled=False`` (or ``PARROT_MCP_DISABLE_GUARDRAILS=1``) disables every
    check, giving absolute full-control behaviour.
    """
    if not enabled:
        return []
    return [reason for pattern, reason in DESTRUCTIVE_PATTERNS if pattern.search(command)]
