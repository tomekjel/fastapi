#!/usr/bin/env python3
"""Disable new perpetual terms in the production OWNER license grid.

No DB mutation, no service restart, no changes to existing grants. Invoked
with --check for a read-only preflight or --apply to write an exact patch.
"""
import argparse
import ast
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil

def patch(source: str) -> str:
    old = 'if choice not in ("KEEP", "3", "6", "12", "CALENDAR", "PERPETUAL"):'
    new = 'if choice not in ("KEEP", "3", "6", "12", "CALENDAR"):'
    if source.count(old) == 1:
        out = source.replace(old, new)
    elif source.count(new) == 1:
        out = source
    else:
        raise ValueError("Unknown OWNER term validator; aborting")
    # Remove only a literal option, leaving other legacy code untouched.
    pattern = r'<option\\b[^>]*\\bvalue\\s*=\\s*["\\\']PERPETUAL["\\\'][^>]*>.*?</option>'
    matches = list(re.finditer(pattern, out, flags=re.I | re.S))
    if len(matches) > 2:
        raise ValueError("Unexpected number of perpetual UI options")
    out = re.sub(pattern, "", out, flags=re.I | re.S)
    ast.parse(out)
    return out

def main():
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    p = Path("app/routers/multiguard_license.py")
    original = p.read_text(encoding="utf-8")
    updated = patch(original)
    if args.check:
        print("PREFLIGHT_OK", "PATCH_REQUIRED" if updated != original else "ALREADY_APPLIED")
        return
    if updated == original:
        print("ALREADY_APPLIED")
        return
    backup = p.with_name(p.name + ".backup-no-perpetual-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    shutil.copy2(p, backup)
    p.write_text(updated, encoding="utf-8")
    if p.read_text(encoding="utf-8") != updated:
        shutil.copy2(backup, p)
        raise RuntimeError("Write verification failed; original restored")
    print("PATCH_OK", "BACKUP", backup)

if __name__ == "__main__":
    main()
