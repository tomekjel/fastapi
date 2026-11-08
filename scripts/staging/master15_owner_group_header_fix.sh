#!/usr/bin/env bash
# MASTER 1.5: correct ONLY mislabelled V4.4 grid headers.
set -Eeuo pipefail
cd /opt/multiservis
P=/opt/multiservis/app/routers/multiguard_license.py
PY=/opt/multiservis/.venv/bin/python
test -f "$P"; test -x "$PY"
BACKUP="/opt/multiservis/backups/master15-owner-header-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$P" "$BACKUP/multiguard_license.py"
committed=0
rollback() {
  rc=$?
  trap - ERR
  if [ "$committed" != 1 ]; then
    cp -a "$BACKUP/multiguard_license.py" "$P"
    systemctl restart multiservis-api.service || true
    echo "ROLLED_BACK $BACKUP" >&2
  fi
  exit "$rc"
}
trap rollback ERR
"$PY" - "$P" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1])
s=p.read_text(encoding="utf-8")
marker="MG15_OWNER_GROUP_HEADER_FIX_V1"
if marker in s: raise SystemExit("ALREADY_PATCHED")
start=s.index("def panel_licenses_grid(")
end=s.index("\ndef ",start+1)
body=s[start:end]
thead=re.search(r"<thead\b[^>]*>(.*?)</thead>",body,re.I|re.S)
if not thead: raise SystemExit("NO_GRID_HEADER")
h=thead.group(1)
cells=list(re.finditer(r"<th\b[^>]*>.*?</th>",h,re.I|re.S))
labels=[re.sub(r"<[^>]*>","",m.group(0)).strip().upper() for m in cells]
print("BEFORE_HEADERS:",labels)
# Explicitly check positions instead of replacing arbitrary text elsewhere.
if len(labels)!=10 or labels[1]!="ID LICENCJI" or labels[5]!="GRUPA":
    raise SystemExit("STOP: header positions differ; no changes")
if "WERSJA" not in labels or "WAŻNA DO" not in labels:
    raise SystemExit("STOP: missing unchanged columns")
targets={1:"GRUPA",5:"LICENCJA"}
for idx in sorted(targets,reverse=True):
    m=cells[idx]
    cell=h[m.start():m.end()]
    new=re.sub(r">[^<>]*</th>$",">"+targets[idx]+"</th>",cell,count=1,flags=re.I)
    if new==cell: raise SystemExit("STOP: unexpected th markup")
    h=h[:m.start()]+new+h[m.end():]
body=body[:thead.start(1)]+h+body[thead.end(1):]
# Marker adjacent to route, not output markup.
body=body.replace("def panel_licenses_grid(", "# "+marker+"\ndef panel_licenses_grid(",1)
s=s[:start]+body+s[end:]
compile(s,str(p),"exec")
p.write_text(s,encoding="utf-8")
print("PASS: header 2=GRUPA, header 6=LICENCJA; all data cells unchanged")
PY
"$PY" - <<'PY'
from app.main import app
assert "/multiguard/panel/licenses-grid" in app.openapi()["paths"]
print("PASS: routes import")
PY
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
"$PY" - <<'PY'
import json,time,urllib.request
for attempt in range(12):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json",timeout=4) as r:
            data=json.load(r)
        assert "/multiguard/panel/licenses-grid" in data["paths"]
        print("PASS: FastAPI HTTP 200")
        break
    except Exception:
        if attempt==11: raise
        time.sleep(1)
PY
committed=1
trap - ERR
echo "OWNER_V44_GROUP_HEADERS_CORRECTED"
echo "BACKUP=$BACKUP"
