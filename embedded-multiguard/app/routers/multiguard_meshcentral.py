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
const tokenFile = process.argv[1];
const meshctrl = process.argv[2];
const requested = process.argv.slice(3);
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
                "--", token_file, meshctrl, "DeviceSharing", "--url", url]

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


def verify_session_node(local_id: str, session_id: str, *, persistent_service: bool = False) -> str:
    """Check exact live MeshCentral node in the pinned consent-only group.

    With persistent_service=True a Windows SCM agent survives many sessions,
    so its display name is not the session UUID. Only a separately authenticated
    installation, accepted backend session and one-to-one node binding may
    invoke this verifier. Group, online state and node identity remain mandatory.
    """
    import json
    import uuid
    session_id = str(uuid.UUID(session_id))
    if not re.fullmatch(r"[A-Za-z0-9@$]{64}", local_id):
        raise MeshCentralError("Nieprawidłowa tożsamość agenta sesji.")
    group = _required("MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID")
    if not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", group):
        raise MeshCentralError("Nieprawidłowa grupa agentów sesji.")
    domain = group.split("/")[1]
    node = f"node/{domain}/{local_id}"
    command = _base_command()
    command[command.index("DeviceSharing")] = "ListDevices"
    output = _run(command + ["--json"])
    if len(output) > 2_000_000:
        raise MeshCentralError("Zbyt duży spis agentów sesji.")
    try:
        records = json.loads(output)
    except ValueError as exc:
        raise MeshCentralError("Nieprawidłowy spis agentów sesji.") from exc
    matches = []
    stack = [records]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            if item.get("_id", item.get("id")) == node:
                matches.append(item)
            for key, value in item.items():
                if isinstance(value, (list, dict)):
                    if key == node and isinstance(value, dict) and "_id" not in value and "id" not in value:
                        stack.append({**value, "_id": node})
                    else:
                        stack.append(value)
    if len(matches) != 1:
        raise MeshCentralError("Agent sesji nie jest jednoznacznie widoczny.")
    record = matches[0]
    # MeshCtrl --json can omit the transient 'conn' field even while the
    # text listing includes it. Check identity/group/name in JSON first;
    # absent connectivity requires an independent, exact-ID text check.
    name = record.get("name")
    if (record.get("meshid") != group
            or not isinstance(name, str)
            or not name.strip()
            or len(name) > 160):
        raise MeshCentralError("Agent nie potwierdził grupy i własnej tożsamości.")
    if not persistent_service and name != f"MultiGuard-{session_id}":
        raise MeshCentralError("Agent nie potwierdził identyfikatora sesji.")
    connected = record.get("conn")
    if connected is None:
        import csv
        listing = _run(command)
        if len(listing) > 2_000_000:
            raise MeshCentralError("Zbyt duży tekstowy spis agentów.")
        statuses = []
        for fields in csv.reader(listing.splitlines(), skipinitialspace=True):
            if len(fields) != 5 or fields[0].strip() != local_id:
                continue
            if fields[1].strip() != name:
                raise MeshCentralError("Niespójna tożsamość agenta MeshCentral.")
            value = fields[3].strip()
            if not re.fullmatch(r"[0-9]+", value):
                raise MeshCentralError("Nieznany status połączenia agenta.")
            statuses.append(int(value))
        if len(statuses) != 1:
            raise MeshCentralError("Nie można jednoznacznie sprawdzić statusu agenta.")
        connected = statuses[0]
    if type(connected) is not int or not (connected & 1):
        raise MeshCentralError("Agent nie jest potwierdzony jako online.")
    return node


def verify_standing_service_node(node_id: str, device_scope: str) -> str:
    """Read-only verification of a previously authorized, exact online SCM node.

    Only a trusted server-side standing authorization record may supply
    device_scope/node_id. A customer consent-group agent cannot satisfy the
    separate unattended service group. Failure never creates/changes a share.
    """
    import csv
    import json

    group_var = {
        "OWNED_WORKSHOP": "MESH_CENTRAL_OWNER_OWNED_MESH_ID",
        "CLIENT_DIAGNOSTIC": "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID",
    }.get(device_scope)
    if group_var is None:
        raise MeshCentralError("Nieznany zakres dostępu serwisowego.")
    group = _required(group_var)
    if not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", group):
        raise MeshCentralError("Nieprawidłowy identyfikator grupy serwisowej.")
    if not re.fullmatch(r"node/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", node_id):
        raise MeshCentralError("Nieprawidłowy identyfikator węzła serwisowego.")
    if node_id.split("/")[1] != group.split("/")[1]:
        raise MeshCentralError("Węzeł jest w innej domenie MeshCentral.")

    # A reused command list (e.g. in test adapters) must not be mutated.
    command = list(_base_command())
    command[command.index("DeviceSharing")] = "ListDevices"
    output = _run(command + ["--json"])
    if len(output) > 2_000_000:
        raise MeshCentralError("Zbyt duży spis urządzeń serwisowych.")
    try:
        devices = json.loads(output)
    except ValueError as exc:
        raise MeshCentralError("Niespójny spis MeshCentral.") from exc
    matches = []
    stack = [devices]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            if item.get("_id", item.get("id")) == node_id:
                matches.append(item)
            for key, value in item.items():
                if isinstance(value, (dict, list)):
                    if key == node_id and isinstance(value, dict) and "id" not in value and "_id" not in value:
                        stack.append({**value, "_id": node_id})
                    else:
                        stack.append(value)
    if len(matches) != 1:
        raise MeshCentralError("Nie znaleziono dokładnie jednego węzła serwisowego.")
    record = matches[0]
    name = record.get("name")
    if (record.get("meshid") != group
            or not isinstance(name, str)
            or not name.strip()
            or len(name) > 160):
        raise MeshCentralError("Węzeł nie należy do zatwierdzonej grupy serwisowej.")
    connected = record.get("conn")
    if connected is None:
        listing = _run(command)
        if len(listing) > 2_000_000:
            raise MeshCentralError("Zbyt duży tekstowy spis węzłów.")
        statuses = []
        local_id = node_id.rsplit("/", 1)[1]
        for fields in csv.reader(listing.splitlines(), skipinitialspace=True):
            if len(fields) != 5 or fields[0].strip() != local_id:
                continue
            if fields[1].strip() != name:
                raise MeshCentralError("Nieprawidłowa nazwa węzła w spisie.")
            value = fields[3].strip()
            if not re.fullmatch(r"[0-9]+", value):
                raise MeshCentralError("Niespójny stan połączenia serwisowego.")
            statuses.append(int(value))
        if len(statuses) != 1:
            raise MeshCentralError("Nie udało się potwierdzić jednego stanu agenta.")
        connected = statuses[0]
    if type(connected) is not int or not (connected & 1):
        raise MeshCentralError("Agent serwisowy jest offline.")
    # MeshCentral accumulates consent from domain, group, device AND user.
    # Group enrollment alone cannot guarantee unattended access: a forced
    # desktop consent prompt at ANY layer will block an absent client.
    # This flag may be set ONLY after an independent on-server examination
    # of domain/user/group consent policy; default is FAIL-CLOSED.
    if os.getenv("MESH_CENTRAL_STANDING_POLICY_ATTESTED","") != "1":
        raise MeshCentralError("Nie potwierdzono skutecznej polityki zgód MeshCentral.")
    device_consent=record.get("consent",0)
    if type(device_consent) is not int or device_consent & 8:
        raise MeshCentralError("Urządzenie wymusza dodatkową zgodę na pulpit.")
    groups_command=list(_base_command())
    groups_command[groups_command.index("DeviceSharing")]="ListDeviceGroups"
    groups_output=_run(groups_command+["--json"])
    if len(groups_output)>2_000_000:
        raise MeshCentralError("Zbyt duży spis grup serwisowych.")
    try:
        group_data=json.loads(groups_output)
    except ValueError as exc:
        raise MeshCentralError("Niespójna odpowiedź listy grup MeshCentral.") from exc
    if isinstance(group_data,dict) and "meshes" in group_data:
        group_data=group_data["meshes"]
    if isinstance(group_data,dict):
        groups=[dict(value, _id=value.get("_id",key))
                for key,value in group_data.items() if isinstance(value,dict)]
    elif isinstance(group_data,list):
        groups=group_data
    else:
        raise MeshCentralError("Nierozpoznany spis grup MeshCentral.")
    matched=[item for item in groups
             if isinstance(item,dict) and item.get("_id")==group]
    if len(matched)!=1:
        raise MeshCentralError("Nie potwierdzono dokładnie jednej grupy serwisowej.")
    group_record=matched[0]
    group_consent=group_record.get("consent",0)
    if (type(group_consent) is not int or group_consent & 8
            or group_record.get("mtype") != 2):
        raise MeshCentralError("Grupa MeshCentral wymusza dodatkową zgodę lub ma zły typ.")
    return node_id


def _create_share(
    node_id: str,
    session_label: str,
    capabilities: Iterable[str],
    duration_minutes: int = 60,
    *,
    workshop_unattended: bool = False,
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
    # Commercial links must always prompt for fresh consent. The separate
    # OWNER workshop path is allowed only after an explicit PRO workshop grant
    # was checked by request_for_owner/connect_for_owner.
    if workshop_unattended:
        # MeshCtrl upstream accepts combined 'notify,bar' flags. Preserve
        # an on-device notification and visible toolbar for any future
        # separately attested service-PRO guest share (never 'none').
        consent = "notify,bar"
    else:
        configured = os.getenv("MESH_CENTRAL_SHARE_CONSENT", "prompt,bar").strip() or "prompt,bar"
        if configured != "prompt,bar":
            raise MeshCentralError("Połączenie z klientem wymaga MeshCentral: prompt,bar.")
        consent = "prompt,bar"

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
        configured = urlsplit(
            os.getenv("MESH_CENTRAL_URL", "").strip() or
            "wss://mesh.multi-servis.pl"
        )
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


def create_share(
    node_id: str,
    session_label: str,
    capabilities: Iterable[str],
    duration_minutes: int = 60,
) -> MeshShare:
    """Fallback for ordinary links: MeshCentral itself requests consent."""
    return _create_share(node_id, session_label, capabilities, duration_minutes)



def verify_session_share_policy(node_id: str) -> None:
    """Re-check device/group desktop consent policy before reusing GUI consent.

    The configured server/user/domain policy is attested separately; dynamic
    group and device restrictions are independently checked on every share.
    """
    import json
    group = _required("MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID")
    # A single-prompt session must use a dedicated MeshCentral group, not the
    # legacy shared group with consent=511 or a standing-service group.
    approved_group = _required("MESH_CENTRAL_SINGLE_PROMPT_MESH_ID")
    if (approved_group != group or
            not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", approved_group)):
        raise MeshCentralError("Grupa jednej zgody nie odpowiada grupie agenta sesji.")
    for other_var in ("MESH_CENTRAL_OWNER_OWNED_MESH_ID",
                      "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID"):
        other = os.getenv(other_var, "").strip()
        if other and other == approved_group:
            raise MeshCentralError("Grupa jednej zgody nie może być grupą serwisową.")
    command = list(_base_command())
    command[command.index("DeviceSharing")] = "ListDevices"
    raw = _run(command + ["--json"])
    if len(raw) > 2_000_000:
        raise MeshCentralError("Zbyt duży spis agentów MeshCentral.")
    try:
        devices = json.loads(raw)
    except ValueError as exc:
        raise MeshCentralError("Nieprawidłowy spis agentów MeshCentral.") from exc
    matched = []
    stack = [devices]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            if item.get("_id", item.get("id")) == node_id:
                matched.append(item)
            for key, value in item.items():
                if isinstance(value, (dict, list)):
                    stack.append(value)
    if len(matched) != 1 or matched[0].get("meshid") != group:
        raise MeshCentralError("Nie można potwierdzić grupy węzła sesji.")
    consent = matched[0].get("consent")
    if type(consent) is not int or consent & 8:
        raise MeshCentralError("Węzeł wymusza dodatkową zgodę na pulpit.")

    groups_command = list(_base_command())
    groups_command[groups_command.index("DeviceSharing")] = "ListDeviceGroups"
    raw_groups = _run(groups_command + ["--json"])
    if len(raw_groups) > 2_000_000:
        raise MeshCentralError("Zbyt duży spis grup MeshCentral.")
    try:
        groups = json.loads(raw_groups)
    except ValueError as exc:
        raise MeshCentralError("Nieprawidłowa lista grup MeshCentral.") from exc
    if isinstance(groups, dict) and "meshes" in groups:
        groups = groups["meshes"]
    if isinstance(groups, dict):
        groups = [dict(value, _id=value.get("_id", key))
                  for key, value in groups.items() if isinstance(value, dict)]
    if not isinstance(groups, list):
        raise MeshCentralError("Nierozpoznana lista grup MeshCentral.")
    found = [item for item in groups
             if isinstance(item, dict) and item.get("_id") == group]
    if len(found) != 1:
        raise MeshCentralError("Nie potwierdzono grupy sesji MeshCentral.")
    policy = found[0].get("consent")
    if (found[0].get("mtype") != 2 or type(policy) is not int
            or policy & 8):
        raise MeshCentralError("Grupa wymusza dodatkową zgodę na pulpit.")



def create_client_approved_share(
    node_id: str,
    session_id: str,
    session_label: str,
    capabilities: Iterable[str],
    duration_minutes: int = 60,
) -> MeshShare:
    """Use the local MultiGuard consent only with attested MeshCentral policy.

    This opt-in is deliberately fail-closed: until the remote group/domain/user
    consent configuration has been independently verified, the old MeshCentral
    prompt remains in force. This is NEVER an unattended permission.
    """
    if os.getenv("MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED", "") != "1":
        return create_share(node_id, session_label, capabilities, duration_minutes)
    # The flag alone is never authority. Re-check exact online node, session
    # identity and pinned consent-only group immediately before creating share.
    verified = verify_session_node(node_id.rsplit("/", 1)[-1], session_id,
                                   persistent_service=True)
    if verified != node_id:
        raise MeshCentralError("Agent nie odpowiada zatwierdzonej sesji.")
    verify_session_share_policy(node_id)
    if "files" in {str(item).lower() for item in capabilities}:
        # File transfer needs separate consent policy; don't broaden desktop approval.
        return create_share(node_id, session_label, capabilities, duration_minutes)
    return _create_share(
        node_id, session_label, ("desktop",), duration_minutes,
        workshop_unattended=True,
    )


def create_workshop_share(
    node_id: str,
    session_label: str,
    capabilities: Iterable[str],
    duration_minutes: int = 60,
) -> MeshShare:
    """OWNER-only workshop grant: visible privacy bar, no per-session prompt.

    Must be called only from the authenticated workshop OWNER path.
    """
    raise MeshCentralError("OWNER_UNATTENDED zablokowany do czasu niezależnego poświadczenia urządzenia.")


def create_standing_service_share(
    node_id: str,
    device_scope: str,
    session_label: str,
    duration_minutes: int = 60,
) -> MeshShare:
    """Desktop-only, visible privacy bar; never a paid PRO session.

    Called only AFTER OWNER backend has verified two separate approvals and
    an active service PRO grant, and the same exact MeshCentral node/group.
    This adapter verifies the live group again just before requesting a link.
    """
    verify_standing_service_node(node_id, device_scope)
    return _create_share(
        node_id, session_label, ("desktop",), duration_minutes,
        workshop_unattended=True,
    )


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

