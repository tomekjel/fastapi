"""Narrow production migration for MultiGuard: paid link + explicit SERVICE rights.

Run only in /opt/multiservis on LXC 103 after production backup.
No license modes/flags are enabled here.
"""
from pathlib import Path
from datetime import datetime, timezone
import ast
import shutil

p = Path("app/routers/multiguard_workshop_remote.py")
s = p.read_text(encoding="utf-8")
old = '''    if pending["status"] in ("ASSIGNED", "PROVISIONED"):
        raise HTTPException(
            409,
            "REMOTE_MODE_CUSTOMER_LICENSE: Ta instalacja ma licencję klienta. Zdalna pomoc wymaga ścieżki "
            "klienta Pro i każdorazowej zgody; sprawdź tryb licencji w MultiGuard.",
        )'''
new = '''    if pending["status"] in ("ASSIGNED", "PROVISIONED"):
        # An explicit OWNER SERVICE selection is independent of the preserved
        # paid KeyGate link. Mere existence of a grant is NOT sufficient.
        with engine.connect() as db:
            selected = license._owner_effective_entitlement_mode(
                db, request.installationId
            )
            grant = _grant(db, request.installationId)
            allowed_service = selected == "SERVICE" and _eligible(grant)
        if not allowed_service:
            raise HTTPException(
                409,
                "REMOTE_MODE_CUSTOMER_LICENSE: Tryb CLIENT wymaga ścieżki Pro "
                "i każdorazowej zgody; serwisowy dostęp jest wyłączony.",
            )'''
if s.count(old) != 1:
    raise SystemExit("ABORT: production source differs; no changes")
if s.count(new) != 0:
    raise SystemExit("ABORT: migration already applied")
changed = s.replace(old, new)
ast.parse(changed, filename=str(p))
backup = p.with_name(p.name + ".backup-service-auth-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
shutil.copy2(p, backup)
p.write_text(changed, encoding="utf-8")
assert p.read_text(encoding="utf-8") == changed
print("PATCH_OK", p)
print("BACKUP", backup)
print("NOTE: restart not performed, mode flags unchanged")
