#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
echo "=== OWNER DELETE 502 — EXACT ROUTE SOURCE DIAGNOSTIC / READ ONLY ==="
/opt/multiservis/.venv/bin/python - <<'PY'
import ast, pathlib, re
root=pathlib.Path("/opt/multiservis")
needle="licenses-grid"
found=[]
for base in (root/"app",root/"scripts"):
    if not base.is_dir(): continue
    for file in base.rglob("*.py"):
        if any(part in {"__pycache__", ".venv","venv"} for part in file.parts):continue
        try: source=file.read_text(encoding="utf-8")
        except (UnicodeError,OSError):continue
        if needle not in source or ("delete" not in source.lower()):continue
        lines=source.splitlines()
        print("SOURCE_FILE",file.relative_to(root))
        try: tree=ast.parse(source)
        except SyntaxError as e:
            print("PARSE_ERROR_LINE",e.lineno);continue
        for node in ast.walk(tree):
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
            start=node.lineno-1
            header="\n".join(lines[max(0,start-12):start+1])
            doc=ast.get_source_segment(source,node) or ""
            if "licenses-grid" not in header and "licenses-grid" not in doc[:280]:continue
            if "/delete" not in header and "/delete" not in doc[:280]:continue
            found.append((file.relative_to(root),node.name,node.lineno))
            print("HANDLER",node.name,"START_LINE",node.lineno,"END_LINE",node.end_lineno)
            for n,line in enumerate(lines[start:node.end_lineno],start=node.lineno):
                # Show control flow, DB table operations, KeyGate calls and error mapping;
                # do not print credentials, user data, response bodies or tokens.
                t=line.strip()
                if not t or t.startswith("#"):continue
                patterns=("keygate","raise ","except ","return ","status_code","HTTPException",
                    "delete ","DELETE ","UPDATE ","INSERT ","SELECT ","revoke","deactiv",
                    "commit","rollback","mesh","transaction","with ","engine.",
                    "redirect","requests.","httpx.","timeout","@router","@app")
                if any(q.lower() in t.lower() for q in patterns):
                    clean=re.sub(r"(['\"])[^'\"]{65,}\1","'[REDACTED]'",t)
                    if re.search(r"secret|password|authorization|credential|token|license_key|api_key",clean,re.I):
                        clean="[SENSITIVE_STATEMENT_OMITTED]"
                    print(f"LINE_{n}",clean[:190])
print("DELETE_HANDLER_COUNT",len(found))
PY
echo "--- PRECISE 502 / API UNIT LOG (METADATA ONLY) ---"
journalctl -u multiservis-api.service --since '2026-11-17 12:06:00 UTC' --until '2026-11-17 12:21:00 UTC' --no-pager -o cat 2>/dev/null | grep -Ei 'keygate|licenses-grid|502 Bad Gateway|502|timeout|Traceback|Exception|ERROR|deactiv|revoke' | sed -E 's/[A-Fa-f0-9]{8}-[A-Fa-f0-9-]{27,}/[UUID]/g;s/[A-Za-z0-9+\/=]{75,}/[REDACTED]/g' | tail -95 || true
echo "=== END READ ONLY; NO KEYGATE REQUEST OR DELETE ==="
