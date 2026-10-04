"""MeshCentral adapter for explicit-consent Multi-Guard remote support."""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import subprocess
from typing import Iterable


@dataclass(frozen=True)
class MeshShare:
    public_id: str
    url: str


class MeshCentralError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise MeshCentralError(f"Brak konfiguracji {name}.")
    return value


def _base_command() -> list[str]:
    node = os.getenv("MESH_CENTRAL_NODE_BIN", "node").strip() or "node"
    meshctrl = _required("MESH_CENTRAL_MESHCTRL_PATH")
    url = _required("MESH_CENTRAL_URL")
    user = _required("MESH_CENTRAL_LOGIN_USER")
    cmd = [node, meshctrl, "DeviceSharing", "--url", url, "--loginuser", user]

    key_file = os.getenv("MESH_CENTRAL_LOGIN_KEY_FILE", "").strip()
    password = os.getenv("MESH_CENTRAL_LOGIN_PASS", "").strip()
    if key_file:
        cmd += ["--loginkeyfile", key_file]
    elif password:
        cmd += ["--loginpass", password]
    else:
        raise MeshCentralError(
            "Skonfiguruj MESH_CENTRAL_LOGIN_KEY_FILE albo MESH_CENTRAL_LOGIN_PASS."
        )
    return cmd


def _run(args: list[str]) -> str:
    timeout = int(os.getenv("MESH_CENTRAL_COMMAND_TIMEOUT_SECONDS", "20"))
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(5, min(timeout, 120)),
            env={**os.environ, "NO_COLOR": "1"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MeshCentralError(
            f"Nie udało się uruchomić integracji MeshCentral: {exc}"
        ) from exc

    output = (completed.stdout or "").strip()
    error = (completed.stderr or "").strip()
    if completed.returncode not in (0, 1):
        raise MeshCentralError(
            (error or output or f"meshctrl exit {completed.returncode}")[:600]
        )
    if error and not output:
        raise MeshCentralError(error[:600])
    return output


def create_share(
    node_id: str,
    session_label: str,
    capabilities: Iterable[str],
    duration_minutes: int = 60,
) -> MeshShare:
    node_id = node_id.strip()
    if not node_id:
        raise MeshCentralError("Brak mesh_node_id dla urządzenia.")

    granted = {item.lower() for item in capabilities}
    if "desktop" not in granted:
        raise MeshCentralError("Sesja zdalna bez pulpitu nie jest obsługiwana.")
    unknown = granted - {"desktop", "files"}
    if unknown:
        raise MeshCentralError("Niedozwolone capability sesji zdalnej.")

    share_type = "desktop,files" if "files" in granted else "desktop"
    duration = max(5, min(int(duration_minutes), 120))
    consent = os.getenv(
        "MESH_CENTRAL_SHARE_CONSENT",
        "prompt,bar",
    ).strip() or "prompt,bar"
    if consent not in {"prompt,bar", "prompt", "notify,bar", "notify"}:
        raise MeshCentralError("Niedozwolona wartość MESH_CENTRAL_SHARE_CONSENT.")

    cmd = _base_command() + [
        "--id", node_id,
        "--add", session_label[:80],
        "--type", share_type,
        "--consent", consent,
        "--duration", str(duration),
    ]
    output = _run(cmd)
    public_match = re.search(r"(?:^|\n)ID:\s*(\S+)", output)
    url_match = re.search(r"(?:^|\n)URL:\s*(\S+)", output)
    if not public_match or not url_match:
        raise MeshCentralError(
            f"MeshCentral nie zwrócił linku sesji: {output[:500]}"
        )
    return MeshShare(public_match.group(1), url_match.group(1))


def revoke_share(node_id: str, public_id: str) -> None:
    if not node_id.strip() or not public_id.strip():
        return
    output = _run(
        _base_command() + [
            "--id", node_id.strip(),
            "--remove", public_id.strip(),
        ]
    )
    if output and "OK" not in output.upper():
        raise MeshCentralError(
            f"Nie potwierdzono usunięcia linku MeshCentral: {output[:500]}"
        )
