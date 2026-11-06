"""Section-level comparison of Cisco IOS configurations for backup, rollback and restoration checks.

A configuration is read as sections: a top-level line and its indented child lines. The rollback for a change is
derived from the backup taken before the change and the configuration read after it, so it restores exactly what
the device had, whatever the device did with the change commands.
"""
from __future__ import annotations

import re

_VOLATILE = re.compile(r"^(Building configuration|Current configuration|! (Last configuration change|NVRAM config last "
                       r"updated|No configuration change since)|ntp clock-period|end$|version \d)")


def sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    header = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped == "!" or _VOLATILE.match(stripped):
            if stripped == "!":
                header = None if not line.startswith(" ") else header
            continue
        if line.startswith(" ") and header is not None:
            out[header].append(" ".join(stripped.split()))
        else:
            header = " ".join(stripped.split())
            out.setdefault(header, [])
    return out


def changed_sections(before: str, after: str) -> list[str]:
    a, b = sections(before), sections(after)
    return sorted(h for h in set(a) | set(b) if a.get(h) != b.get(h))


def equivalent(before: str, after: str) -> bool:
    return not changed_sections(before, after)


def _negate(line: str) -> str:
    return line[3:] if line.startswith("no ") else "no " + line


def rollback_commands(backup: str, current: str) -> list[str]:
    """Configuration-mode commands that turn `current` back into `backup` for every differing section."""
    old, new = sections(backup), sections(current)
    commands: list[str] = []
    for header in sorted(set(old) | set(new)):
        before, after = old.get(header), new.get(header)
        if before == after:
            continue
        if before is None:  # created by the change
            commands.append(_negate(header) if not header.startswith("interface ") else f"no {header}")
            continue
        commands.append(header)
        if after is not None:
            for child in after:
                if child not in before:
                    commands.append(" " + _negate(child))
        for child in before:
            if after is None or child not in after:
                commands.append(" " + child)
        if not before and after is None:
            continue
        if header.startswith(("interface ", "router ", "ip access-list ", "vlan ", "line ")):
            commands.append(" exit")
    return commands
