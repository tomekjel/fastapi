#!/usr/bin/env bash
# MASTER 1.5 OWNER V4.4 — exact-cell Mesh group integration.
# Run inside LXC 103 as root; transaction-safe source patch + rollback.
set -Eeuo pipefail
cd /opt/multiservis
P=/opt/multiservis/app/routers/multiguard_license.py
M=/opt/multiservis/app/main.py
R=/opt/multiservis/app/routers
PY=/opt/multiservis/.venv/bin/python
test -f "$P"; test -f "$M"; test -x "$PY"
test "$(id -u)" -eq 0

BACKUP="/opt/multiservis/backups/master15-mesh-owner-v44-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$P" "$BACKUP/multiguard_license.py"
cp -a "$M" "$BACKUP/main.py"
for name in master15_owner_mesh_group_policy.py master15_owner_mesh_sync_engine.py master15_owner_mesh_retry_router.py; do
    if test -e "$R/$name"; then
        echo "STOP: file already exists $name"; exit 1
    fi
done

done_ok=0
rollback() {
    rc=$?
    trap - ERR
    if [ "$done_ok" != 1 ]; then
        cp -a "$BACKUP/multiguard_license.py" "$P"
        cp -a "$BACKUP/main.py" "$M"
        rm -f "$R/master15_owner_mesh_group_policy.py" "$R/master15_owner_mesh_sync_engine.py" "$R/master15_owner_mesh_retry_router.py"
        systemctl restart multiservis-api.service || true
        echo "OWNER_MESH_ROLLBACK_DONE: $BACKUP" >&2
    fi
    exit "$rc"
}
trap rollback ERR

echo "=== OWNER MESH / FETCH MODULES ==="
for name in master15_owner_mesh_group_policy.py master15_owner_mesh_sync_engine.py master15_owner_mesh_retry_router.py; do
    gh api "repos/tomekjel/fastapi/contents/scripts/staging/$name" --jq '.content' \
        | tr -d '\n' | base64 -d > "$R/$name"
    chmod 0644 "$R/$name"
done

echo "=== OWNER V4.4 EXACT PATCH ==="
"$PY" - "$P" "$M" <<'PY'
from pathlib import Path
import re,sys

p=Path(sys.argv[1]); main=Path(sys.argv[2])
src=p.read_text(encoding="utf-8")
if "MG15_GROUP_MESH_V1" in src:
    raise SystemExit("STOP: already patched")
begin=src.index("def panel_licenses_grid(")
stop=src.index("\ndef ",begin+1)
part=src[begin:stop]

# Required production V4.4 invariants. Never touch "ID licencji".
h=re.search(r'<thead\b[^>]*>(.*?)</thead>',part,flags=re.I|re.S)
if not h: raise SystemExit("STOP: V4.4 header missing")
labels=[re.sub(r'<[^>]*>','',m).strip().lower() for m
        in re.findall(r'<th\b[^>]*>.*?</th>',h.group(1),flags=re.I|re.S)]
expect=["komputer / id","id licencji","klient","zlecenie","wersja",
        "licencja","ważna do","kontakt","kanał","operacje"]
if labels!=expect: raise SystemExit("STOP: unexpected V4.4 column order "+repr(labels))
html=part[h.start():h.end()]
if html.count("<th>Licencja</th>") != 1: raise SystemExit("STOP: Licencja heading ambiguous")
part=part[:h.start()]+html.replace("<th>Licencja</th>","<th>Grupa mesh</th>",1)+part[h.end():]

old='''        license_type_cell = f'<span class="mg-license-kind" title="Aktualny typ licencji">{license_type}</span>' '''
# Source may not have trailing whitespace.
old=old.rstrip()
if part.count(old)!=1: raise SystemExit("STOP: license type cell not unique")
new='''        # MG15_GROUP_MESH_V1: this is the sixth V4.4 column ONLY.
        # Current Select value does NOT affect group until confirmed Save.
        from app.routers import master15_owner_mesh_sync_engine as _mesh_sync
        if r["installation_id"]:
            with engine.connect() as _group_db:
                _group_name, _group_state, _group_attempts = _mesh_sync.get_status(
                    _group_db, r["installation_id"])
        else:
            _group_name, _group_state, _group_attempts = "Brak", "Czeka", 0
        license_type_cell = (
            f'<span class="mg-mesh-label">{_panel_escape(_group_name)}</span>'
        )
        if _group_state == "Ponów" and can_edit:
            license_type_cell += (
                f'<form class="mg-mesh-retry-form" method="post" '
                f'action="/multiguard/panel/licenses-grid/{lid}/mesh-retry">'
                f'<input type="hidden" name="csrf_token" value="{token}">'
                '<button type="submit" class="mg-mesh-retry" '
                'title="Ponów synchronizację z MeshCentral">↻ Ponów</button>'
                '</form>'
            )
        else:
            license_type_cell += (
                f'<small class="mg-mesh-state">{_panel_escape(_group_state)}</small>'
            )'''
part=part.replace(old,new,1)

# two lines in the current 46px V4.4 row
css='''
    /* MG15_GROUP_MESH_V1: compact V4.4 two-line info, no extra height */
    .mg16 .mg-mesh-label{display:block;white-space:nowrap;overflow:hidden;
      text-overflow:ellipsis;font:600 11px/14px system-ui,'Segoe UI',Arial,sans-serif}
    .mg16 .mg-mesh-state{display:block;white-space:nowrap;overflow:hidden;
      text-overflow:ellipsis;font:10px/12px system-ui,'Segoe UI',Arial,sans-serif;
      margin-top:1px;color:#aec4df}
    .mg16 .mg-mesh-retry-form{display:block;margin:0;padding:0;line-height:12px}
    .mg16 .mg-mesh-retry{border:0!important;box-shadow:none!important;
      padding:0!important;margin:1px 0 0!important;background:transparent!important;
      font:10px/12px system-ui,'Segoe UI',Arial,sans-serif;color:#aec4df!important;
      cursor:pointer!important;white-space:nowrap}
'''
if part.count("</style>")!=1: raise SystemExit("STOP: owner grid CSS ambiguous")
part=part.replace("</style>",css+"</style>",1)

# Crucial: no modification to ID license, edition select, Version or Save.
assert '<td>{license_cell}</td>' in part
assert '<td>{edition_cell}</td><td>{license_type_cell}</td>' in part
assert '<td>{version_cell}</td><td class="mg-actions">{actions}</td>' in part
assert '/licenses-grid/{lid}/save' in part
src=src[:begin]+part+src[stop:]
compile(src,str(p),"exec")
p.write_text(src,encoding="utf-8")

# Add a narrowly scoped, post-success OWNER Save hook plus guarded retry
# route registration. Both are appended AFTER the production app is defined;
# this avoids the prior NameError from premature router import.
main_src=main.read_text(encoding="utf-8")
if "MG15_MESH_OWNER_HOOK_V1" in main_src: raise SystemExit("STOP: hook exists")
hook='''
# MG15_MESH_OWNER_HOOK_V1: register only after existing FastAPI app definition.
from app.routers import master15_owner_mesh_retry_router as _mg15_mesh_retry
app.include_router(_mg15_mesh_retry.router)

import asyncio as _mg15_asyncio
import re as _mg15_re
from uuid import UUID as _mg15_UUID
from sqlalchemy import text as _mg15_text
from app.database import engine as _mg15_engine
from app.routers import master15_owner_mesh_sync_engine as _mg15_sync

_MG15_SAVE_PATH = _mg15_re.compile(
    r"^/multiguard/panel/licenses-grid/([0-9a-fA-F-]{36})/save$")
_MG15_TASKS = set()

def _mg15_task_finished(task):
    _MG15_TASKS.discard(task)
    try:
        task.result()
    except Exception:
        import logging
        logging.getLogger("multiguard.owner.mesh").exception("OWNER Mesh sync failed")

@app.middleware("http")
async def _mg15_mesh_after_owner_save(request,call_next):
    path=request.url.path
    match=_MG15_SAVE_PATH.fullmatch(path) if request.method=="POST" else None
    response=await call_next(request)
    # Original OWNER form validated authentication, CSRF and KeyGate before
    # returning 303. Failed/unconfirmed saves MUST never queue a Mesh change.
    if match and response.status_code==303:
        try:
            link_id=_mg15_UUID(match.group(1))
            with _mg15_engine.begin() as db:
                iid=db.execute(_mg15_text("""
                    SELECT installation_id FROM guard.license_links
                    WHERE id=:id AND installation_id IS NOT NULL
                """),{"id":link_id}).scalar_one_or_none()
                if iid is not None:
                    _mg15_sync.queue_after_owner_save(db,iid)
            if iid is not None:
                task=_mg15_asyncio.create_task(
                    _mg15_asyncio.to_thread(
                        _mg15_sync.run_pending_installation,_mg15_engine,iid))
                _MG15_TASKS.add(task)
                task.add_done_callback(_mg15_task_finished)
        except Exception:
            # License was committed already. Do not undo it or fabricate OK.
            import logging
            logging.getLogger("multiguard.owner.mesh").exception(
                "OWNER Mesh sync enqueue failed")
    return response
'''
main_src += "\n"+hook
compile(main_src,str(main),"exec")
main.write_text(main_src,encoding="utf-8")
print("PASS: only sixth V4.4 column changed; post-303 Save hook installed")
PY

echo "=== PREFLIGHT APP IMPORT AND ROUTES BEFORE RESTART ==="
"$PY" -m py_compile "$P" "$M" "$R"/master15_owner_mesh_*.py
"$PY" - <<'PY'
from app.main import app
routes=app.openapi()["paths"]
for path in ("/multiguard/panel/licenses-grid",
             "/multiguard/panel/licenses-grid/{link_id}/mesh-retry"):
    if path not in routes: raise SystemExit("MISSING_ROUTE:"+path)
print("PASS: existing OWNER panel and retry route in FastAPI")
PY

echo "=== CREATE ONLY NEW GROUP STATUS TABLE ==="
"$PY" - <<'PY'
from app.database import engine
from app.routers.master15_owner_mesh_sync_engine import ensure_schema
with engine.begin() as db: ensure_schema(db)
print("PASS: owner_mesh_group_sync schema")
PY

echo "=== RESTART AND VERIFY LIVE API ==="
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
"$PY" - <<'PY'
import time,urllib.request,json
for i in range(15):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json",timeout=5) as r:
            data=json.load(r)
        paths=data["paths"]
        assert "/multiguard/panel/licenses-grid" in paths
        assert "/multiguard/panel/licenses-grid/{link_id}/mesh-retry" in paths
        print("PASS: LOCAL_API_HTTP_200_AND_MESH_RETRY")
        break
    except Exception:
        if i==14: raise
        time.sleep(1)
PY
done_ok=1
trap - ERR
echo "OWNER_GRUPA_MESH_V1_DEPLOYED"
echo "BACKUP=$BACKUP"
echo "SYNC_STARTS_ONLY_AFTER_SUCCESSFUL_OWNER_SAVE"
