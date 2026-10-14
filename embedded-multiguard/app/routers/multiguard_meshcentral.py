"""MeshCentral adapter for explicit-consent Multi-Guard remote support."""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import subprocess
from typing import Iterable
from urllib.parse import urlsplit


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


# Executed inside Node, not a shell. Credentials are read by this process
# and added only to JavaScript's process.argv (never to the OS command line).
# The token file is protected by root:multiservis 0640 on the OWNER host.
_MESHCTRL_TOKEN_BOOTSTRAP = r"""
"use strict";
const fs = require("node:fs");
const meshctrl = process.argv[1];
const requested = process.argv.slice(2);
const tokenFile = process.env.MESH_CENTRAL_TOKEN_FILE;
let token;
try {
    token = JSON.parse(fs.readFileSync(tokenFile, "utf8"));
} catch (_) {
    process.stderr.write("MeshCentral: token file missing or invalid.\\n");
    process.exit(2);
}
if (!token || typeof token.username !== "string" ||
        !token.username.startsWith("~t:") ||
        typeof token.password !== "string" || !token.password) {
    process.stderr.write("MeshCentral: token credentials invalid.\\n");
    process.exit(2);
}
process.argv = [process.execPath, meshctrl, ...requested,
                "--loginuser", token.username,
                "--loginpass", token.password];
require(meshctrl);
"""


def _base_command() -> list[str]:
    # Owner production already provisions this root:multiservis 0640 file.
    # Use it by default so no passwords or systemd drop-in edits are needed.
    default_token = "/etc/multiservis/meshcentral-token.json"
    configured_token = os.getenv("MESH_CENTRAL_TOKEN_FILE", "").strip()
    token_file = configured_token or default_token
    token_mode = bool(configured_token) or os.path.isfile(default_token)

    node = os.getenv("MESH_CENTRAL_NODE_BIN", "node").strip() or "node"
    if token_mode:
        if not os.path.isfile(token_file):
            raise MeshCentralError("Plik tokenu MeshCentral jest niedostępny.")
        meshctrl = os.getenv("MESH_CENTRAL_MESHCTRL_PATH", "").strip() or (
            "/opt/multiservis-meshctrl/node_modules/meshcentral/meshctrl.js"
        )
        url = os.getenv("MESH_CENTRAL_URL", "").strip() or (
            "wss://mesh.multi-servis.pl"
        )
        return [node, "-e", _MESHCTRL_TOKEN_BOOTSTRAP,
                "--", meshctrl, "DeviceSharing", "--url", url]

    # Existing non-token installations retain explicit legacy configuration.
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
            "Skonfiguruj MESH_CENTRAL_TOKEN_FILE, "
            "MESH_CENTRAL_LOGIN_KEY_FILE albo MESH_CENTRAL_LOGIN_PASS."
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
    if completed.returncode != 0:
        raise MeshCentralError(
            (error or output or f"meshctrl exit {completed.returncode}")[:600]
        )
    if error and not output:
        raise MeshCentralError(error[:600])
    # MeshCtrl 1.2.5 can exit with code 0 after an authentication failure.
    # Never interpret that success code as a successful remote operation.
    if not output or output.startswith(("Invalid login", "Unable to connect")):
        raise MeshCentralError("MeshCtrl nie potwierdził połączenia.")
    return output


def verify_registered_node(node_id: str) -> bool:
    """Read-only verification against this OWNER's MeshCentral inventory.

    Do not accept a client-supplied identifier based on format or hostname
    alone. Return False on a missing node; fail closed on API/JSON errors.
    """
    if not re.fullmatch(r"node/[^/]*/[A-Za-z0-9@$]{64}", node_id):
        return False
    cmd = _base_command()
    # With token-file mode MeshCtrl receives a Node bootstrap first.
    # Change the action without relying on a fixed argv index.
    action_index = cmd.index("DeviceSharing")
    cmd[action_index] = "ListDevices"
    output = _run(cmd + ["--json"])
    if len(output) > 2_000_000:
        raise MeshCentralError("Zbyt duża odpowiedź MeshCentral ListDevices.")
    try:
        import json
        devices = json.loads(output)
    except ValueError as exc:
        raise MeshCentralError("MeshCentral nie zwrócił poprawnego spisu urządzeń.") from exc

    # MeshCtrl versions can return a list, an object of groups, or a
    # mapping of node IDs. In every case require exact node identity.
    found = False
    stack = [devices]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            identity = item.get("_id", item.get("id"))
            if identity == node_id:
                found = True
                break
            for key, val in item.items():
                if key == node_id and isinstance(val, dict):
                    found = True
                    break
                if isinstance(val, (list, dict)):
                    stack.append(val)
            if found:
                break
    return found


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
    # The direct OWNER API also returns this URL. Validate it here so no
    # caller can accidentally forward an untrusted MeshCtrl URL to a user.
    share_url = url_match.group(1)
    try:
        returned = urlsplit(share_url)
        configured = urlsplit(_required("MESH_CENTRAL_URL"))
        if (returned.scheme != "https"
                or not returned.hostname
                or not configured.hostname
                or returned.hostname.lower() != configured.hostname.lower()
                or returned.username is not None
                or returned.password is not None
                or returned.fragment
                or (returned.port or 443) != (
                    configured.port or (
                        443 if configured.scheme in {"wss", "https"} else 80
                    )
                )):
            raise ValueError("Untrusted MeshCentral share URL")
        # Reading .port above also rejects malformed ports such as :99999.
        # A matching hostname with an unrelated port is a different service.
    except ValueError as exc:
        raise MeshCentralError("MeshCentral zwrócił niebezpieczny adres sesji.") from exc
    return MeshShare(public_match.group(1), share_url)


def _share_absent_from_listing(node_id: str, public_id: str) -> bool:
    """Trust absence only in a COMPLETE MeshCtrl DeviceSharing listing.

    Upstream prints one '----------' section per share, including required
    Identifier/Type/UserId/Guest Name/User Consent and ending in URL.
    A truncated final share must not be mistaken for proof of removal.
    """
    listing = _run(_base_command() + ["--id", node_id]).strip()
    if listing == "No device sharing links for this device.":
        return True
    blocks = re.split(r"(?m)^----------[ \t]*\r?$", listing)
    if len(blocks) < 2 or blocks[0].strip():
        raise MeshCentralError("Nieznany format listy udostępnień MeshCentral.")

    ids = set()
    required = ("Identifier:", "Type:", "UserId:", "Guest Name:", "User Consent:")
    optional = ("Start Time:", "Expire Time:", "Duration:", "Recurring:")
    for block in blocks[1:]:
        lines = [line.strip() for line in block.strip().splitlines()]
        if (len(lines) < 6
                or any(not lines[i].startswith(key) for i, key in enumerate(required))
                or not lines[-1].startswith("URL:")
                or not lines[-1][len("URL:"):].strip()
                or any(not line.startswith(optional) for line in lines[5:-1])):
            raise MeshCentralError("Niekompletna lista udostępnień MeshCentral.")
        share_id = lines[0][len("Identifier:"):].strip()
        if not share_id or share_id in ids:
            raise MeshCentralError("Nieprawidłowy identyfikator udostępnienia MeshCentral.")
        ids.add(share_id)
    return public_id not in ids


def revoke_share(node_id: str, public_id: str) -> None:
    """Remove a share, or confirm it was already removed after a lost reply."""
    node_id = node_id.strip()
    public_id = public_id.strip()
    if not node_id or not public_id:
        raise MeshCentralError("Brak identyfikatora węzła lub linku MeshCentral.")
    cmd = _base_command() + ["--id", node_id, "--remove", public_id]
    try:
        result = _run(cmd)
        if result.strip().upper() == "OK":
            return
        failure = "MeshCtrl nie potwierdził usunięcia: " + (result[:200] or "brak odpowiedzi")
    except MeshCentralError as exc:
        failure = "MeshCtrl nie zwrócił potwierdzenia: " + str(exc)[:200]

    # After network loss, the remove may already have taken effect. Do not
    # trust the error text: check the server's currently listed share IDs.
    try:
        if _share_absent_from_listing(node_id, public_id):
            return
    except MeshCentralError as exc:
        raise MeshCentralError(f"{failure}. Odczyt stanu nieudany: {exc}") from exc
    raise MeshCentralError(f"{failure}. Link nadal jest aktywny na serwerze.")
