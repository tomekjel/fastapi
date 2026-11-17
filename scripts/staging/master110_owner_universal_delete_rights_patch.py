#!/usr/bin/env python3
"""MASTER110 universal OWNER / MeshCentral delete gate: deploy once, no device IDs."""
from __future__ import annotations
import ast
import datetime
import pathlib
import shutil
import sys

PATH=pathlib.Path("/opt/multiservis/app/routers/multiguard_license.py")
BACKUP_DIR=pathlib.Path("/opt/multiservis/backups")
original=PATH.read_text(encoding="utf-8")
MARKER="MASTER110_UNIVERSAL_DELETE_RIGHTS_V1"
if MARKER in original:
    print("ALREADY_PATCHED",MARKER)
    sys.exit(0)

# Live code signature: require exact, unique anchors, and never guess.
preflight_anchor='    # After all prechecks, revoke this computer\'s KeyGate licence. The'
remove_anchor="""        except mesh.MeshCentralError as exc:
            # A response can be lost after a successful removal. Read the
            # inventory instead of treating a network error as definite failure.
            if worker.inventory().get(node):
                raise HTTPException(
                    502, "MeshCentral nie potwierdzil usuniecia agenta."
                ) from exc
"""
if original.count(preflight_anchor)!=1 or original.count(remove_anchor)!=1:
    raise SystemExit("STOP: CODE CONTRACT DOES NOT MATCH. NO CHANGES.")

# At this stage, owner has already verified node-to-installation ownership,
# session state, cross-schema FKs, allowed Mesh group and live inventory.
# UserInfo is read-only. Deny only when MeshCentral explicitly reports a
# non-admin group link with no Manage Devices permission; unknown rights fail
# closed during the later real command rather than granting any new capability.
preflight = '''    # MASTER110_UNIVERSAL_DELETE_RIGHTS_V1 — before ANY irreversible KeyGate revoke.
    # Use live Mesh identity and group-level access rights. Never rely on hostname.
    if verified_mesh_nodes:
        import json as _mg_json
        try:
            _mg_cmd = mesh._base_command()
            if _mg_cmd.count("DeviceSharing") != 1:
                raise mesh.MeshCentralError("Nieznana struktura integracji MeshCentral.")
            _mg_cmd[_mg_cmd.index("DeviceSharing")] = "UserInfo"
            _mg_user = _mg_json.loads(mesh._run(_mg_cmd + ["--json"]))
            if not isinstance(_mg_user, dict):
                raise mesh.MeshCentralError("MeshCentral nie zwrocil danych konta.")
            _mg_siteadmin = _mg_user.get("siteadmin", 0)
            try:
                _mg_admin = int(_mg_siteadmin) != 0
            except (ValueError, TypeError):
                _mg_admin = False
            _mg_links = _mg_user.get("links") or {}
            if not isinstance(_mg_links, dict):
                _mg_links = {}
            if not _mg_admin:
                for _mg_node in verified_mesh_nodes:
                    _mg_entries = inventory.get(_mg_node, [])
                    if not _mg_entries:
                        continue
                    _mg_gid = _mg_entries[0].get("meshid")
                    _mg_link = _mg_links.get(_mg_gid)
                    if isinstance(_mg_link, dict) and _mg_link.get("rights") is not None:
                        try:
                            _mg_rights = int(_mg_link["rights"])
                        except (ValueError, TypeError):
                            _mg_rights = 0
                        if not (_mg_rights & 4):
                            raise HTTPException(
                                403,
                                "Konto integracji MeshCentral nie ma prawa zarzadzania "
                                "urzadzeniami w grupie. Administrator musi nadac Manage Devices."
                            )
        except HTTPException:
            raise
        except (mesh.MeshCentralError, ValueError) as exc:
            raise HTTPException(
                503, "Nie mozna zweryfikowac uprawnien MeshCentral. "
                "Licencja nie zostala cofnieta ani usunieta."
            ) from exc

'''
replacement = """        except mesh.MeshCentralError as exc:
            # MASTER110_UNIVERSAL_DELETE_RIGHTS_V1: a lost reply might still
            # follow successful removal. Verify live inventory before deciding.
            if worker.inventory().get(node):
                _mg_message = str(exc).lower()
                if any(_mg_bad in _mg_message for _mg_bad in (
                    "denied", "forbidden", "unauthorized", "permission denied",
                    "access denied"
                )):
                    raise HTTPException(
                        403,
                        "MeshCentral odmowil usuniecia agenta (brak uprawnien "
                        "Manage Devices dla konta integracji). "
                        "Nie usunieto danych komputera z OWNER."
                    ) from exc
                raise HTTPException(
                    502, "MeshCentral nie potwierdzil usuniecia agenta. "
                    "Sprawdz uprawnienia i polaczenie konta integracji."
                ) from exc
"""
updated=original.replace(preflight_anchor, preflight+preflight_anchor,1)
updated=updated.replace(remove_anchor,replacement,1)
ast.parse(updated)
assert updated.count(MARKER)==3
assert "DELETE FROM guard.license_links" in updated
assert "DELETE FROM guard.installations" in updated
assert "RemoveDevice" in updated
assert "revoked" in updated.lower()
assert updated.count("mesh._auto_mesh_command(\"RemoveDevice\")")==original.count("mesh._auto_mesh_command(\"RemoveDevice\")")
BACKUP_DIR.mkdir(parents=True,exist_ok=True)
backup=BACKUP_DIR/("multiguard_license.py.before-universal-delete-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
if backup.exists(): raise SystemExit("STOP BACKUP_COLLISION")
shutil.copy2(PATH,backup)
temp=PATH.with_name(PATH.name+".master110-new")
try:
    temp.write_text(updated,encoding="utf-8")
    import py_compile
    py_compile.compile(str(temp),doraise=True)
    temp.chmod(PATH.stat().st_mode)
    temp.replace(PATH)
    print("PATCH_APPLIED",MARKER)
    print("BACKUP",backup)
except BaseException:
    temp.unlink(missing_ok=True)
    if MARKER in PATH.read_text(encoding="utf-8"):
        shutil.copy2(backup,PATH)
    raise
