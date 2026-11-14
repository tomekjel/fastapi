"""Pure SemVer and signed Windows NSIS asset helpers for Multi-Guard.

Shared by the API release endpoint and GitHub release sync. Does not
initialize the database or import FastAPI.
"""
from __future__ import annotations

import re

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
TAG_RE = re.compile(
    r"^v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
    r"-(?P<channel>TEST(?:-preview)?|LICENSE_TEST|PILOT|STABLE)$",
    re.IGNORECASE,
)
_NSIS_X64 = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*_x64(?:-[A-Za-z0-9._-]+)?-setup\.exe",
    re.IGNORECASE,
)


def semver_key(value: str) -> tuple:
    """Correct SemVer precedence, including prereleases.

    beta.9 < beta.10 < stable for the same major.minor.patch.
    Build metadata does not affect ordering.
    """
    match = _SEMVER_RE.fullmatch((value or "").strip())
    if match is None:
        raise ValueError(f"Nieprawidłowa wersja SemVer: {value}")
    major, minor, patch = (int(v) for v in match.group(1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return (major, minor, patch, 1, ())
    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            if len(identifier) > 1 and identifier.startswith("0"):
                raise ValueError(f"Nieprawidłowy identyfikator SemVer: {value}")
            identifiers.append((0, int(identifier)))
        else:
            identifiers.append((1, identifier))
    return (major, minor, patch, 0, tuple(identifiers))


def is_windows_x64_nsis(filename: str) -> bool:
    """Accept x64 NSIS artifacts, including unique Tauri hash/time suffixes."""
    return bool(_NSIS_X64.fullmatch(filename or ""))
