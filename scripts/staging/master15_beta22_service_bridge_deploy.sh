#!/usr/bin/env bash
# MASTER 1.5 beta22: scoped production API enablement for signed dormant SERVICE.
# Deliberately no OWNER save, Mesh move, Windows SCM or session authorization.
set -Eeuo pipefail
test "$(id -u)" -eq 0
cd /opt/multiservis
export PYTHONPATH=/opt/multiservis
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
PY=/opt/multiservis/.venv/bin/python
R=/opt/multiservis/app/routers/master15_owner_profile_bridge.py
BK="/opt/multiservis/backups/master15-beta22-service-$(date -u +%Y%m%d-%H%M%S)"
TMP=$(mktemp -d)
mkdir -p "$BK"
test -f "$R"
cp -a "$R" "$BK/owner_profile_bridge.py"
modified=0
rollback(){
  local rc=$?
  trap - ERR
  if test "$modified" -eq 1;then
    cp -a "$BK/owner_profile_bridge.py" "$R"
    systemctl restart multiservis-api.service || true
    echo "BETA22_SERVICE_BACKEND_SOURCE_ROLLBACK_RESTORED" >&2
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap rollback ERR
gh api 'repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_profile_bridge.py?ref=mg/master15-beta22-service-bridge' --jq .content | base64 -d > "$TMP/new-bridge.py"
gh api 'repos/tomekjel/fastapi/contents/scripts/staging/master15_beta22_service_target_constraint_migration.py?ref=mg/master15-beta22-service-bridge' --jq .content | base64 -d > "$TMP/service-constraint.py"
"$PY" -m py_compile "$TMP/new-bridge.py" "$TMP/service-constraint.py"
"$PY" - "$R" "$TMP/new-bridge.py" "$TMP/patched.py" <<'PY'
from pathlib import Path
import ast,sys
live=Path(sys.argv[1]).read_text(encoding="utf-8")
candidate=Path(sys.argv[2]).read_text(encoding="utf-8")
def extract(src,name):
    tree=ast.parse(src)
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
    if len(functions)!=1:raise RuntimeError("EXPECTED_ONE_"+name)
    f=functions[0]
    return src.splitlines(keepends=True),f
def substitute_function(old,new,name):
    old_lines,of=extract(old,name)
    new_lines,nf=extract(new,name)
    # Replace the complete audited function only. All other production routes,
    # credentials, consent handlers, workshop checks and patches are preserved.
    return "".join(old_lines[:of.lineno-1])+ "".join(new_lines[nf.lineno-1:nf.end_lineno])+ "".join(old_lines[of.end_lineno:])
if '"SERVICE":"ServiceDormant"' in live:
    raise RuntimeError("LIVE_SERVICE_DORMANT_BRIDGE_ALREADY_INSTALLED")
if 'expected={"STANDARD":"ClientDormant","PRO":"ClientRunning"}' not in live:
    raise RuntimeError("EXPECTED_LEGACY_REPORT_GUARD_NOT_FOUND")
if 'AND expires_at>now() FOR UPDATE' not in live:
    raise RuntimeError("EXPIRING_RESERVATION_SAFETY_FIX_MISSING")
patched=substitute_function(live,candidate,"_owner_target")
patched=patched.replace('expected={"STANDARD":"ClientDormant","PRO":"ClientRunning"}',
                        'expected={"STANDARD":"ClientDormant","PRO":"ClientRunning",\n                  "SERVICE":"ServiceDormant"}',1)
compile(patched,str(sys.argv[1]),"exec")
Path(sys.argv[3]).write_text(patched,encoding="utf-8")
assert '_owner_effective_entitlement_mode(db,iid)' in patched
assert '"SERVICE":"ServiceDormant"' in patched
assert 'AND expires_at>now() FOR UPDATE' in patched
print("PASS: production OWNER bridge modified only in entitlement target and signed receipt mapping")
PY
install -m 0644 "$TMP/patched.py" "$R"
modified=1
"$PY" -m py_compile "$R"
"$PY" "$TMP/service-constraint.py"
systemctl restart multiservis-api.service
ready=0
for i in $(seq 1 30);do
  if systemctl is-active --quiet multiservis-api.service && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null;then
    ready=1;break
  fi
  sleep 1
done
test "$ready" -eq 1
"$PY" - <<'PY'
from app.main import app
from app.routers import master15_owner_profile_bridge as bridge
from sqlalchemy import text
from app.database import engine
paths=app.openapi().get("paths",{})
for endpoint in ("/v1/multi-guard/owner-profile-grant","/v1/multi-guard/owner-profile-report"):
 assert "post" in paths.get(endpoint,{}), "OWNER_SIGNED_ENDPOINT_NOT_AVAILABLE"
from inspect import getsource
assert '"SERVICE":"ServiceDormant"' in getsource(bridge.owner_profile_report)
with engine.connect() as db:
 rows=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).all()
 assert len(rows)==1, "ASUS_ROG_IDENTITY_AMBIGUOUS"
print("PASS: signed OWNER Service bridge imported and routes live")
print("PASS: production remains untouched except approved signed Service profile grant/receipt and target CHECK")
PY
modified=0
trap - ERR
rm -rf "$TMP"
echo 'MASTER15_BETA22_SERVICE_BRIDGE_DEPLOY_PASS'
echo "BACKUP=$BK"
