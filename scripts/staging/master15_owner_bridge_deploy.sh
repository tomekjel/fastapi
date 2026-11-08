#!/usr/bin/env bash
# MASTER 1.5 / 3-of-6 — narrow deploy. Run ONLY inside LXC 103 as root.
# Preserve the full live OWNER panel, routes, and original license module.
set -Eeuo pipefail
[ "$(id -u)" -eq 0 ] || { echo "MUST_BE_ROOT" >&2; exit 1; }
BASE="/opt/multiservis"
ROUTER="$BASE/app/routers"
MAIN="$BASE/app/main.py"
PYTHON="$BASE/.venv/bin/python"
[ -x "$PYTHON" ] || { echo "MISSING_VENV" >&2; exit 1; }
[ -f "$MAIN" ] || { echo "MISSING_LIVE_MAIN" >&2; exit 1; }
[ -f "$ROUTER/multiguard_workshop_remote.py" ] || { echo "MISSING_LIVE_WORKSHOP_REMOTE" >&2; exit 1; }
[ -f "$ROUTER/multiguard_license.py" ] || { echo "MISSING_LIVE_LICENSE" >&2; exit 1; }
command -v gh >/dev/null || { echo "GITHUB_CLI_REQUIRED" >&2; exit 1; }

# Recover installed GitHub credentials from existing deployment settings.
if [ -d /root/.config/gh-tomekjel ]; then export GH_CONFIG_DIR=/root/.config/gh-tomekjel; fi
gh auth status -h github.com >/dev/null 2>&1 || { echo "GITHUB_AUTH_REQUIRED" >&2; exit 1; }
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BASE/backups/master15-owner-bridge-$STAMP"
mkdir -p "$BACKUP"
cp -a "$MAIN" "$BACKUP/main.py"
for name in multiguard_owner_profile_grant.py master15_owner_profile_bridge.py; do
    [ ! -e "$ROUTER/$name" ] || { echo "FILE_ALREADY_PRESENT:$name" >&2; exit 1; }
done

restored=0
rollback() {
  rc=$?
  trap - ERR
  if [ "$restored" -eq 0 ]; then
    cp -a "$BACKUP/main.py" "$MAIN"
    rm -f "$ROUTER/master15_owner_profile_bridge.py" "$ROUTER/multiguard_owner_profile_grant.py"
    systemctl restart multiservis-api.service || true
    echo "ROLLED_BACK $BACKUP" >&2
  fi
  exit "$rc"
}
trap rollback ERR

# Fetch exactly two modules, not the old embedded license/router bundle.
gh api repos/tomekjel/fastapi/contents/embedded-multiguard/app/routers/multiguard_owner_profile_grant.py \
    --jq .content | tr -d '\n' | base64 -d > "$ROUTER/multiguard_owner_profile_grant.py"
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_profile_bridge.py \
    --jq .content | tr -d '\n' | base64 -d > "$ROUTER/master15_owner_profile_bridge.py"
chmod 0644 "$ROUTER/multiguard_owner_profile_grant.py" "$ROUTER/master15_owner_profile_bridge.py"

# Preflight exact helpers from deployed OWNER code. No schema migrations.
"$PYTHON" - "$MAIN" "$ROUTER" <<'PY'
import sys
from pathlib import Path
main = Path(sys.argv[1])
root = Path(sys.argv[2])
license_source = (root / "multiguard_license.py").read_text(encoding="utf-8")
workshop_source = (root / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
required = {
  "license": ("def _owner_effective_entitlement_mode", "def _signing_key"),
  "workshop": ("def _service_transition_sessions", "def _schema"),
}
for label, source in (("license", license_source), ("workshop", workshop_source)):
    for name in required[label]:
        if name not in source:
            raise SystemExit(f"STOP: live {label} missing required helper: {name}")
for file in ("multiguard_owner_profile_grant.py", "master15_owner_profile_bridge.py"):
    compile((root/file).read_bytes(),str(root/file),"exec")
source = main.read_text(encoding="utf-8")
import_line="from app.routers import master15_owner_profile_bridge"
include_line="app.include_router(master15_owner_profile_bridge.router)"
if import_line in source or include_line in source:
    raise SystemExit("STOP: bridge already registered")
lines = source.splitlines()
# Insert after other router imports, not inside a function.
indices=[i for i,line in enumerate(lines) if line.startswith("from app.routers import ")]
if not indices:
    raise SystemExit("STOP: cannot locate top-level FastAPI router imports")
lines.insert(indices[-1]+1,import_line)
source="\n".join(lines)+"\n"
anchor="app.include_router(multiguard_license.router)"
if anchor not in source:
    raise SystemExit("STOP: cannot locate live license router registration")
source=source.replace(anchor,anchor+"\n"+include_line,1)
compile(source,str(main),"exec")
main.write_text(source,encoding="utf-8")
PY

"$PYTHON" -m py_compile "$MAIN" "$ROUTER/master15_owner_profile_bridge.py" "$ROUTER/multiguard_owner_profile_grant.py"
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
"$PYTHON" - <<'PY'
import json
import urllib.request
url="http://127.0.0.1:8000/openapi.json"
try:
    data=json.load(urllib.request.urlopen(url,timeout=10))
except Exception:
    # Public API may be behind a different local port; external route check
    # by the operator is still required if 8000 is not the actual bind.
    print("LOCAL_OPENAPI_NOT_AVAILABLE_AT_8000")
else:
    for endpoint in ("/v1/multi-guard/owner-profile-grant",
                     "/v1/multi-guard/owner-profile-report"):
        if endpoint not in data["paths"]:
            raise SystemExit("MISSING_LIVE_ROUTE:"+endpoint)
    print("OWNER_BRIDGE_ROUTES_PRESENT")
PY
restored=1
trap - ERR
echo "DEPLOYED_OWNER_BRIDGE"
echo "BACKUP=$BACKUP"
echo "NO_LICENSE_OR_WORKSHOP_MODULE_REPLACEMENT"
