#!/usr/bin/env python3
"""Fail-closed MultiGuard remote admission patch, for production CT103.

Run from /opt/multiservis. Performs source guards, backups, AST validation;
does not activate OWNER switching. Never replace prod routers with GitHub routers.
"""
import ast
from pathlib import Path
from datetime import datetime, timezone
import shutil

root = Path("app/routers")
remote = root / "multiguard_remote.py"
workshop = root / "multiguard_workshop_remote.py"

def one(src, marker, replacement, label):
    n=src.count(marker)
    if n != 1: raise RuntimeError(f"{label}: expected one anchor, got {n}")
    return src.replace(marker, replacement, 1)

# This query maps client internal guard.installations.id to the canonical
# pending_installations.installation_id used by the SERVICE transition table.
client_check = '''        # Prevent customer Pro sessions while local Windows profile is changing.
        canonical_iid = connection.execute(text("""
            SELECT p.installation_id
            FROM guard.installations gi
            JOIN guard.pending_installations p
              ON p.installation_id::text = gi.installation_external_id::text
            WHERE gi.id=:iid
        """), {"iid": support["installation_id"]}).scalar_one_or_none()
        if canonical_iid is None:
            raise HTTPException(409, "Nie uzgodniono tożsamości instalacji Windows.")
        if connection.execute(text("""
            SELECT 1 FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' LIMIT 1
        """), {"iid": canonical_iid}).first():
            raise HTTPException(409, "Trwa zmiana profilu Windows.")
'''
# For connect, session/installation already locked by FOR UPDATE OF rs,gi.
connect_check = '''        canonical_iid = connection.execute(text("""
            SELECT p.installation_id
            FROM guard.installations gi
            JOIN guard.pending_installations p
              ON p.installation_id::text = gi.installation_external_id::text
            WHERE gi.id=:iid
        """), {"iid": row["installation_id"]}).scalar_one_or_none()
        if canonical_iid is None:
            raise HTTPException(409, "Nie uzgodniono tożsamości instalacji Windows.")
        if connection.execute(text("""
            SELECT 1 FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' LIMIT 1
        """), {"iid": canonical_iid}).first():
            raise HTTPException(409, "Trwa zmiana profilu Windows.")
'''
# A fresh link must be invalidated if a profile reservation appears while
# MeshCentral is creating it.
post_check = '''            if connection.execute(text("""
                SELECT 1
                FROM guard.workshop_profile_transitions
                WHERE installation_id=:iid AND state='RESERVED'
                LIMIT 1
            """), {"iid": canonical_iid}).first():
                raise HTTPException(409, "Profil zmieniono podczas zestawiania połączenia.")
'''

src_r = remote.read_text(encoding="utf-8")
if "workshop_profile_transitions" in src_r:
    raise RuntimeError("Client router already contains transition guard; inspect manually")
src_r = one(src_r, '''        if support["support_status"] in {"RESOLVED", "CANCELLED"}:''',
            client_check + '''        if support["support_status"] in {"RESOLVED", "CANCELLED"}:''',
            "Pro create")
src_r = one(src_r, '''        if row["status"] not in {"CONSENTED", "CONNECT_READY", "ACTIVE"}:''',
            connect_check + '''        if row["status"] not in {"CONSENTED", "CONNECT_READY", "ACTIVE"}:''',
            "Pro connect")
src_r = one(src_r, '''            # If MeshCentral was slow enough for the new lease to expire,''',
            post_check + '''            # If MeshCentral was slow enough for the new lease to expire,''',
            "Pro connect postshare")

src_w = workshop.read_text(encoding="utf-8")
if "workshop_profile_transitions" in src_w:
    raise RuntimeError("SERVICE router already contains transition guard; inspect manually")
w_guard = '''        if db.execute(text("""
            SELECT 1 FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' LIMIT 1
        """), {"iid": iid}).first():
            raise HTTPException(409, "Trwa zmiana profilu Windows.")
'''
src_w = one(src_w, '''        if _open(db, iid):
            raise HTTPException(409,"Ten komputer ma już otwartą sesję.")''',
            w_guard + '''        if _open(db, iid):
            raise HTTPException(409,"Ten komputer ma już otwartą sesję.")''', "Service request")
src_w = one(src_w, '''        if row["status"] not in ("CONSENTED","CONNECT_READY","ACTIVE"):''',
            '''        if db.execute(text("""
            SELECT 1 FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' LIMIT 1
        """), {"iid": row["installation_id"]}).first():
            raise HTTPException(409, "Trwa zmiana profilu Windows.")
''' + '''        if row["status"] not in ("CONSENTED","CONNECT_READY","ACTIVE"):''',
            "Service connect")
src_w = one(src_w, '''            if share_expires <= _now():''',
            '''            if db.execute(text("""
                SELECT 1 FROM guard.workshop_profile_transitions
                WHERE installation_id=:iid AND state='RESERVED' LIMIT 1
            """), {"iid": iid}).first():
                raise HTTPException(409, "Profil zmieniono podczas zestawiania połączenia.")
''' + '''            if share_expires <= _now():''',
            "Service connect postshare")

ast.parse(src_r); ast.parse(src_w)
# All preconditions and validation finish before touching either file.
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backups = []
try:
    for path in (remote,workshop):
        backup=path.with_name(path.name + ".before-service-admission-" + stamp)
        shutil.copy2(path,backup); backups.append((path,backup))
    remote.write_text(src_r,encoding="utf-8")
    workshop.write_text(src_w,encoding="utf-8")
    assert ast.parse(remote.read_text()) and ast.parse(workshop.read_text())
except Exception:
    for path,backup in backups: shutil.copy2(backup,path)
    raise
print("REMOTE_SESSION_GUARDS_PATCHED")
for _,backup in backups: print("BACKUP",backup)
print("OWNER_SWITCH_FLAG_UNCHANGED")
