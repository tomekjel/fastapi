#!/usr/bin/env python3
"""OWNER V4.4: surgical, fail-closed extension of the actual 146-line Save.

Does NOT replace Save with the older GitHub variant. Existing name, paid-plan
and release-channel handling is preserved, including stale-data checks.
New term/edition choices are routed to a separate guarded helper. Both new
execution switches remain disabled until full KeyGate/Mesh integration.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = Path("/opt/multiservis")
ROUTERS = ROOT / "app/routers"
LICENSE = ROUTERS / "multiguard_license.py"
POLICY = ROUTERS / "multiguard_entitlement_modes.py"
THEME = ROUTERS / "multiguard_panel_theme.py"
EXPECTED_LIVE_SHA256 = "7086ed8317e4957d4e6b8958a2a3259eef3b56d6ec93aa18f5989c90d538e049"
EXPECTED_THEME_SHA256 = "0e63d2c54ddb5036237aa2ba53ca4c73e71aa86e23c24280e1001dddd1d778d7"
OLD_POLICY_BLOB = "986a113ce82ccb1b094bcef7ba27d22b36d7011c"
NEW_POLICY_BLOB = "295b46f5d116ccf910da8a12f6cc0d722392c6b7"
POLICY_COMMIT = "4a5de60495457abbb533c4915e507c5244476569"

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\\0" + data).hexdigest()

def functions(source: str):
    return {node.name: node for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

def function_text(source: str, name: str) -> str:
    node = functions(source).get(name)
    if node is None:
        raise RuntimeError("Production function missing: " + name)
    rows = source.splitlines(keepends=True)
    return "".join(rows[node.lineno - 1:node.end_lineno])

def replace_function(source: str, name: str, replacement: str) -> str:
    node = functions(source).get(name)
    if node is None:
        raise RuntimeError("Production function missing: " + name)
    rows = source.splitlines(keepends=True)
    return "".join(rows[:node.lineno - 1]) + replacement.rstrip() + "\\n" + "".join(rows[node.end_lineno:])

def inject_before_route(source: str, name: str, text_to_add: str) -> str:
    node = functions(source).get(name)
    if node is None:
        raise RuntimeError("Production function missing: " + name)
    first = min([node.lineno] + [deco.lineno for deco in node.decorator_list])
    rows = source.splitlines(keepends=True)
    return "".join(rows[:first-1]) + text_to_add.rstrip() + "\\n\\n" + "".join(rows[first-1:])

def once(source: str, old: str, new: str, name: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError(f"Unsafe V4.4 anchor for {name}: count={source.count(old)}")
    return source.replace(old, new, 1)

HELPER = '''
def _owner_v44_grid_term_selection(
    link_id, operation_id, friendly_name, target_edition, release_channel,
    expected_plan, expected_end, expected_channel, expected_name,
    term_choice, term_date, payment_confirmed,
):
    """New OWNER term and mode action; legacy V4.4 Save is untouched."""
    from app.routers.multiguard_entitlement_modes import plan_grid_license_change
    from fastapi.responses import RedirectResponse

    choice = term_choice.strip().upper()
    edition = target_edition.strip().upper()
    if edition not in ("STANDARD", "PRO", "SERVICE"):
        raise HTTPException(400, "Nieprawidłowa edycja.")
    if choice not in ("KEEP", "3", "6", "12", "CALENDAR", "PERPETUAL"):
        raise HTTPException(400, "Nieprawidłowy wybór okresu.")
    if choice != "CALENDAR" and term_date.strip():
        raise HTTPException(400, "Data musi dotyczyć wyboru kalendarzowego.")
    if not 0 < len(operation_id.hex) == 32:
        raise HTTPException(400, "Nieprawidłowa operacja.")

    _ensure_schema()
    with engine.connect() as con:
        row = con.execute(text("""
            SELECT * FROM guard.license_links WHERE id=:id
        """), {"id": link_id}).mappings().one_or_none()
        if not row or row["installation_id"] is None:
            raise HTTPException(404, "Nie znaleziono licencji komputera.")
        iid = row["installation_id"]
        current_name = str(con.execute(text("""
            SELECT friendly_name FROM guard.owner_installation_labels
            WHERE installation_external_id=:iid
        """), {"iid": iid}).scalar_one_or_none() or "")
        current_channel = str(row["release_channel"] or "").upper()
        if (str(row["plan_code"] or "") != expected_plan
                or (_iso(row["valid_until"]) if row["valid_until"] else "") != expected_end
                or current_channel != expected_channel
                or current_name != expected_name):
            raise HTTPException(409, "Dane zmieniły się. Odśwież tabelę.")
        if (" ".join(friendly_name.strip().split()) != current_name
                or release_channel.strip().upper() != current_channel):
            raise HTTPException(409,
                "Zmień nazwę i kanał osobno; okres licencji musi mieć własny zapis.")
        mode = _owner_effective_entitlement_mode(con, iid)
        paid_edition = "PRO" if row["plan_code"] == "multi_guard_pro" else "STANDARD"
        selected_edition = "SERVICE" if mode == "SERVICE" else paid_edition
        service_end = con.execute(text("""
            SELECT valid_until FROM guard.workshop_grants
            WHERE installation_id=:iid
        """), {"iid": iid}).scalar_one_or_none()

    try:
        plan = plan_grid_license_change(
            current_mode=mode, current_edition=selected_edition,
            target_edition=edition, term_choice=choice, term_date=term_date,
            now=_utcnow(), paid_valid_until=row["valid_until"],
            service_valid_until_current=service_end, paid_edition=paid_edition,
            explicit_paid_perpetual_supported=False,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    action = plan["action"]

    if action in ("ENTER_SERVICE", "SERVICE_TERM", "RESTORE_PAID"):
        # Independent service rights can be enabled only AFTER full signed
        # discovery, Windows and Mesh transitions have passed. Both gates
        # must be explicitly turned on by OWNER in a later audited stage.
        if not (
            str(_setting("MULTIGUARD_MODE_SWITCH_ENABLED", "false")).lower() in ("true","1","yes")
            and str(_setting("MULTIGUARD_OWNER_GRID_SERVICE_ENABLED", "false")).lower() in ("true","1","yes")
        ):
            raise HTTPException(409, "Przełączanie trybu serwisowego jeszcze wyłączone.")
        _owner_select_effective_mode(
            link_id, operation_id, plan["mode"], mode,
            "Zmiana trybu w tabeli właściciela",
            choice if plan["mode"] == "SERVICE" else "",
            term_date if plan["mode"] == "SERVICE" else "",
        )
    elif action in ("PAID_EXTEND", "PAID_CALENDAR"):
        if str(_setting("MULTIGUARD_OWNER_GRID_PAID_TERM_ENABLED", "false")).lower() not in ("true","1","yes"):
            raise HTTPException(409, "Zapis nowych okresów płatnych jeszcze wyłączony.")
        if action == "PAID_EXTEND":
            if payment_confirmed != "yes":
                raise HTTPException(400, "Potwierdź otrzymanie płatności.")
            # The existing per-licence extension handler appends to remaining
            # validity and is idempotent, never generates a second KeyGate key.
            _extend_active_license(
                iid, int(choice), operation_id,
                source="WEB", payment_confirmed=True, by_installation=True,
                expected_end=row["valid_until"],
            )
        else:
            chosen = plan["valid_until"]
            if chosen is None or row["valid_until"] is None or chosen >= row["valid_until"]:
                raise HTTPException(409,
                    "Późniejszą datę ustaw przez płatne przedłużenie.")
            _shorten_owner_license(link_id, operation_id, row["valid_until"],
                                   chosen, "Zmiana końca ważności przez OWNER")
    else:
        raise HTTPException(409,
            "Nie można łączyć zmiany edycji z okresem ani tworzyć bezterminowego KeyGate.")

    return RedirectResponse(
        "/multiguard/panel/licenses-grid", status_code=303,
        headers={"Cache-Control": "private, no-store"},
    )
'''

def patched(source: str) -> str:
    fn = function_text(source, "panel_grid_save_row")
    if "def _owner_v44_grid_term_selection(" in source or "term_choice: str = Form" in fn:
        raise RuntimeError("V4.4 term bridge already present; refuse duplicate")
    fn = once(fn,
        '    csrf_token: str = Form(...),\\n    _: None = Depends(_panel_auth),',
        '    csrf_token: str = Form(...),\\n'
        '    term_choice: str = Form("KEEP"),\\n'
        '    term_date: str = Form(""),\\n'
        '    payment_confirmed: str = Form(""),\\n'
        '    _: None = Depends(_panel_auth),',
        "optional independent term fields")
    fn = once(fn,
        '    if confirmed != "yes":\\n        raise HTTPException(400,"Potwierdź zapis zmian.")',
        '    if confirmed != "yes":\\n        raise HTTPException(400,"Potwierdź zapis zmian.")\\n'
        '    if (term_choice.strip().upper() != "KEEP" or term_date.strip()\\n'
        '            or target_edition.strip().upper() == "SERVICE"):\\n'
        '        return _owner_v44_grid_term_selection(\\n'
        '            link_id, operation_id, friendly_name, target_edition,\\n'
        '            release_channel, expected_plan, expected_end,\\n'
        '            expected_channel, expected_name, term_choice, term_date,\\n'
        '            payment_confirmed,\\n'
        '        )\\n',
        "route new term choices outside existing Save")
    fn = once(fn,
        '        row,old_name=check_state(con)\\n        iid=row["installation_id"]',
        '        row,old_name=check_state(con)\\n        iid=row["installation_id"]\\n'
        '        if iid and _owner_effective_entitlement_mode(con, iid) != "CLIENT":\\n'
        '            raise HTTPException(409, "Najpierw przywróć tryb licencji klienta.")',
        "paid Save must not overwrite selected service mode")
    result = replace_function(source, "panel_grid_save_row", fn)
    result = inject_before_route(result, "panel_grid_save_row", HELPER)
    compile(result, str(LICENSE), "exec")
    before = functions(source)
    after = functions(result)
    allowed = {"panel_grid_save_row", "_owner_v44_grid_term_selection"}
    if set(after) - set(before) != {"_owner_v44_grid_term_selection"}:
        raise RuntimeError("Unexpected new functions outside OWNER term helper")
    if set(before) - set(after):
        raise RuntimeError("Existing V4.4 functions disappeared")
    for name in set(before) - allowed:
        if ast.dump(before[name], include_attributes=False) != ast.dump(
            after[name], include_attributes=False
        ):
            raise RuntimeError("V4.4 protected function changed: " + name)
    for marker in (
        "expected_channel: str = Form", "expected_name: str = Form",
        "release_channel: str = Form", "def check_state(con,after_plan=False)",
        "channel_changed=channel!=", "if name_changed or channel_changed:",
        "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.",
    ):
        if marker not in result:
            raise RuntimeError("Protected V4.4 anchor removed: " + marker)
    return result

def status():
    req = urllib.request.Request(
        "https://api.multi-servis.pl/multiguard/panel/licenses-grid",
        headers={"Cache-Control": "no-cache"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code

def no_open_sessions():
    import sys
    sys.path.insert(0, str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as c:
        for table in ("guard.remote_sessions", "guard.workshop_remote_sessions"):
            exists = c.execute(text("SELECT to_regclass(:table_name)"),
                               {"table_name": table}).scalar_one_or_none()
            if exists is None:
                continue
            opened = c.execute(text(
                "SELECT count(*) FROM " + table +
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
            )).scalar_one()
            if opened:
                raise RuntimeError(f"Otwarte sesje w {table}: {opened}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if digest(LICENSE.read_bytes()) != EXPECTED_LIVE_SHA256:
        raise RuntimeError("V4.4 production source hash changed; no writes")
    if digest(THEME.read_bytes()) != EXPECTED_THEME_SHA256:
        raise RuntimeError("V4.4 theme hash changed; no writes")
    if git_blob(POLICY.read_bytes()) != OLD_POLICY_BLOB:
        raise RuntimeError("Existing six-variant policy changed; no writes")
    url = ("https://raw.githubusercontent.com/tomekjel/fastapi/" +
           POLICY_COMMIT + "/embedded-multiguard/app/routers/multiguard_entitlement_modes.py")
    with urllib.request.urlopen(url, timeout=25) as response:
        policy_data = response.read()
    if git_blob(policy_data) != NEW_POLICY_BLOB:
        raise RuntimeError("New OWNER grid planner digest mismatch")
    compile(policy_data, str(POLICY), "exec")
    prepared = patched(LICENSE.read_text())
    before = status()
    if before not in (401, 403):
        raise RuntimeError(f"Protected panel returned HTTP {before}")
    print("V4.4 EXISTING SAVE: PRESERVED NAME / EDITION / CHANNEL")
    print("V4.4 GRID HTML / CSS: BYTE FOR BYTE UNCHANGED")
    print("OWNER SIX TERM PLANNER: PREPARED")
    print("NEW TERM AND SERVICE OPERATIONS: FLAGS OFF")
    print("KEYGATE / MESH: NO MUTATIONS")
    if not args.apply:
        print("V4.4 SURGICAL PREFLIGHT: PASS (DRY RUN)")
        return
    # Changing the module restarts FastAPI. Refuse active client connections.
    no_open_sessions()
    backup = ROOT / ("backup-mg-owner-v44-surgical-" +
                     datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(LICENSE, backup / LICENSE.name)
    shutil.copy2(POLICY, backup / POLICY.name)
    written = False
    try:
        for target, data in ((LICENSE, prepared.encode()), (POLICY, policy_data)):
            fd, temporary = tempfile.mkstemp(prefix=".mg-v44-surgical-", dir=ROUTERS)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(data)
                os.chmod(temporary, 0o644)
                os.replace(temporary, target)
                written = True
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        subprocess.run(["systemctl", "restart", "multiservis-api.service"],
                       check=True, timeout=40)
        for _ in range(14):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", "multiservis-api.service"],
                check=False, timeout=10).returncode == 0
            if active and status() == before:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI or OWNER panel failed postrestart")
        print("V4.4 SURGICAL OWNER BACKEND: APPLIED")
        print("V4.4 GRID HTML / CSS: UNCHANGED")
        print("NEW LICENCE MODES: STILL DISABLED")
        print("KEYGATE / MESH / LICENSE RECORDS: UNCHANGED")
        print("BACKUP:", backup)
    except Exception:
        if written:
            shutil.copy2(backup / LICENSE.name, LICENSE)
            shutil.copy2(backup / POLICY.name, POLICY)
            subprocess.run(["systemctl", "restart", "multiservis-api.service"],
                           check=False, timeout=40)
        raise

if __name__ == "__main__":
    main()
