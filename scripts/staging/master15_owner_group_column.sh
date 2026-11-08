#!/usr/bin/env bash
# MASTER 1.5 OWNER licences grid: narrow presentation patch, fail closed.
# No changing OWNER saving, licence issuance or MeshCentral; no false "OK".
set -Eeuo pipefail
cd /opt/multiservis
P=/opt/multiservis/app/routers/multiguard_license.py
PY=/opt/multiservis/.venv/bin/python
test -f "$P"; test -x "$PY"
BACKUP="/opt/multiservis/backups/master15-owner-group-column-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"; cp -a "$P" "$BACKUP/multiguard_license.py"
done_ok=0
rollback() {
  rc=$?
  trap - ERR
  if [ "$done_ok" -ne 1 ]; then
    cp -a "$BACKUP/multiguard_license.py" "$P"
    systemctl restart multiservis-api.service || true
    echo "OWNER_GROUP_ROLLBACK $BACKUP" >&2
  fi
  exit "$rc"
}
trap rollback ERR
"$PY" - "$P" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1])
s=p.read_text(encoding="utf-8")
if "MG15_OWNER_GROUP_CELL_V1" in s:
    raise SystemExit("STOP: group column already patched")
start=s.index("def panel_licenses_grid(")
end=s.index("\ndef ",start+1)
body=s[start:end]
# Only replace the single license ID cell in the existing grid; preserve
# all other table content, including one Save per row and Version column.
old=re.search(
    r"(?m)^        if license_raw:\n"
    r"(?:(?!^        if client_raw:)[\s\S])*?"
    r"(?=^        if client_raw:)",
    body
)
if not old or "license_cell =" not in old.group(0) or "mg-copy" not in old.group(0):
    raise SystemExit("STOP: unexpected original V4.4 licence-cell layout")
new='''        # MG15_OWNER_GROUP_CELL_V1: target group is not proof of Mesh membership.
        # Until a separate MeshCentral verification/ack writes a confirmed
        # state, display Czeka, never a fabricated OK.
        _mg_group_name = (
            "Serwis" if edition == "SERVICE" else
            "Klient" if edition == "PRO" else "Standard"
        )
        _mg_group_state = "Czeka"
        if r["installation_id"]:
            with engine.connect() as _mg_group_db:
                _mg_transition = _mg_group_db.execute(text("""
                    SELECT state,target_mode
                    FROM guard.workshop_profile_transitions
                    WHERE installation_id=:iid
                """), {"iid": r["installation_id"]}).mappings().first()
                if _mg_transition and _mg_transition["state"] == "RESERVED":
                    _mg_group_state = "Przenoszenie…"
        license_cell = (
            f'<span class="mg-group-name" title="Docelowa grupa MeshCentral">'
            f'{_mg_group_name}</span>'
            f'<small class="mg-group-state" title="Status synchronizacji grupy MeshCentral">'
            f'{_mg_group_state}</small>'
        )
'''
body=body[:old.start()]+new+body[old.end():]
# Update ONLY the owner grid table's column heading by source matching a
# single header containing the old label. Avoid other screens entirely.
header=re.search(r"(?s)(?P<a><thead[^>]*>)(?P<b>.*?)(?P<c></thead>)",body)
if not header:
    raise SystemExit("STOP: missing OWNER grid header")
h=header.group("b")
labels=list(re.finditer(r"<th\b[^>]*>Licencja</th>",h,flags=re.I))
if len(labels)!=1:
    raise SystemExit(f"STOP: ambiguous Licencja heading count={len(labels)}")
h=h[:labels[0].start()]+re.sub("Licencja","Grupa",labels[0].group(0),count=1,flags=re.I)+h[labels[0].end():]
body=body[:header.start("b")]+h+body[header.end("b"):]
# No extra lines, and never increase the fixed V4.4 row height.
css='''
    /* MG15_OWNER_GROUP_CELL_V1 compact two-line target/status */
    .mg16 .mg-group-name{display:block;max-width:100%;white-space:nowrap;
      overflow:hidden;text-overflow:ellipsis;font-weight:600;font-size:11px;
      line-height:14px}
    .mg16 .mg-group-state{display:block;max-width:100%;white-space:nowrap;
      overflow:hidden;text-overflow:ellipsis;font-size:10px;line-height:12px;
      margin-top:1px;color:#a9c2d9}
'''
# Insert CSS before existing style closure, within owner page only.
if body.count("</style>")!=1:
    raise SystemExit("STOP: cannot safely locate owner grid styles")
body=body.replace("</style>",css+"</style>",1)
s=s[:start]+body+s[end:]
assert s.count('name="target_edition"')>=1
assert 'f\'<td>{version_cell}</td><td class="mg-actions">{actions}</td></tr>\'' in s
assert "def _mg_v44_grid_transform" in s
compile(s,str(p),"exec")
p.write_text(s,encoding="utf-8")
print("PASS: OWNER V4.4 Grupa / 2-line / no false OK / Save unchanged")
PY
"$PY" - <<'PY'
from app.main import app
paths=app.openapi().get("paths",{})
assert "/multiguard/panel/licenses-grid" in paths
assert "/v1/multi-guard/owner-profile-grant" in paths
print("PASS: OWNER routes compile and load")
PY
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
"$PY" - <<'PY'
import time,urllib.request,json
for i in range(12):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json",timeout=4) as r:
            d=json.load(r)
        assert "/multiguard/panel/licenses-grid" in d["paths"]
        print("PASS: FastAPI local OpenAPI")
        break
    except Exception:
        if i==11: raise
        time.sleep(1)
PY
done_ok=1
trap - ERR
echo "OWNER_GROUP_COLUMN_V1_DEPLOYED"
echo "BACKUP=$BACKUP"
echo "MESH_VERIFICATION_PENDING: statuses show Czeka / Przenoszenie, never false OK"
