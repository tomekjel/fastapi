#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
import uuid,inspect
old=uuid.UUID('a29b7aba-fb1f-48cb-8f22-3eadc2aa4727')
new=uuid.UUID('d521b000-5351-4026-aca0-d5e8ca373849')
print('=== MASTER110 ASUS DELETE 502 — KEYGATE AND MESH PREFLIGHT (READ ONLY) ===')
with engine.connect() as db:
    q=text('''SELECT l.id,l.installation_id,l.lifecycle,l.keygate_license_id,
                     p.hostname,p.status
              FROM guard.license_links l
              JOIN guard.pending_installations p ON p.installation_id=l.installation_id
              WHERE l.id IN (:old,:new)''')
    rows=db.execute(q,{'old':old,'new':new}).mappings().all()
    if len(rows)!=2:
        print('STOP: EXPECTED_EXACTLY_TWO_ASUS_LICENSES');raise SystemExit(2)
    for r in rows:
        label='OLD' if r['id']==old else 'CURRENT'
        print(label,'INSTALLATION_ID',r['installation_id'],'LIFECYCLE',r['lifecycle'],'HOST',r['hostname'],'INSTALL_STATUS',r['status'])
    old_row=next(r for r in rows if r['id']==old)
    current=next(r for r in rows if r['id']==new)
    if old_row['hostname']!='ROG' or current['hostname']!='ROG' or old_row['lifecycle']!='REVOKED' or current['lifecycle']!='ACTIVE':
        print('STOP: SAFETY_CONDITIONS_CHANGED');raise SystemExit(3)
    try:
        remote=lic._keygate_license(old_row['keygate_license_id'])
        print('OLD_KEYGATE_STATUS',str(remote.get('status','MISSING')).upper() if isinstance(remote,dict) else 'UNEXPECTED_RESPONSE')
    except Exception as exc:
        print('OLD_KEYGATE_CHECK_ERROR',type(exc).__name__)
    try:
        remote=lic._keygate_license(current['keygate_license_id'])
        print('CURRENT_KEYGATE_STATUS',str(remote.get('status','MISSING')).upper() if isinstance(remote,dict) else 'UNEXPECTED_RESPONSE')
    except Exception as exc:
        print('CURRENT_KEYGATE_CHECK_ERROR',type(exc).__name__)
    cols=lambda t:set(db.execute(text('SELECT column_name FROM information_schema.columns WHERE table_schema=\'guard\' AND table_name=:t'),{'t':t}).scalars())
    pending_cols=cols('pending_installations')
    for t in ('pending_installations','installations','workshop_mesh_nodes','owner_mesh_group_sync'):
        fields=cols(t)
        if not fields:continue
        id_col='installation_id' if 'installation_id' in fields else 'installation_external_id' if 'installation_external_id' in fields else None
        if not id_col:continue
        selected=[c for c in ('mesh_node_id','mesh_last_verified_node_id','requested_group','status','last_error') if c in fields]
        if not selected:continue
        expr=','.join('"' + c + '"' for c in selected)
        try:
            data=db.execute(text('SELECT '+expr+' FROM guard.'+t+' WHERE CAST('+id_col+' AS text)=:iid LIMIT 10'),{'iid':str(old_row['installation_id'])}).mappings().all()
            for row in data:
                shown={k:('[PRESENT]' if 'node_id' in k and v else '[ABSENT]' if 'node_id' in k else str(v)) for k,v in row.items()}
                print('OLD_'+t.upper(),shown)
        except Exception as exc: print('MESH_DB_READ_ERROR',t,type(exc).__name__)
print('=== DELETE HANDLER EXACT 502 CONTROL FLOW — SOURCE (NO SECRETS) ===')
from pathlib import Path
source=Path('/opt/multiservis/app/routers/multiguard_license.py').read_text(encoding='utf-8').splitlines()
for a,b in [(7440,7471),(7498,7522),(7544,7560)]:
    print('SOURCE_RANGE',a,b)
    for lineno in range(a,b+1):
        line=source[lineno-1].rstrip()
        # Skip long literals and anything that might include a secret.
        if any(k in line.lower() for k in ('token','secret','password','api_key','credential','license_key','authorization')):
            print(lineno,'[SENSITIVE_SOURCE_OMITTED]');continue
        print(lineno,line[:175])
print('=== END — NO DELETE NO REVOKE NO MESH COMMAND ===')
PY
