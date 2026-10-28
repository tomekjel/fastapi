#!/usr/bin/env python3
"""Safely add MeshCentral guest auto-connect only to the OWNER remote viewer."""
from pathlib import Path
import argparse
import os
import py_compile
import shutil
import sys
from datetime import datetime, timezone

OLD = """          if (url.protocol !== 'https:' || url.hostname !== 'mesh.multi-servis.pl') throw Error('Niezaufany adres MeshCentral.');
          if (tab) tab.location.replace(url.href);"""
NEW = """          if (url.protocol !== 'https:' || url.hostname !== 'mesh.multi-servis.pl') throw Error('Niezaufany adres MeshCentral.');
          // Enable auto-connect on the authenticated MeshCentral guest page only.
          url.searchParams.set('mgautoconnect', '1');
          if (tab) tab.location.replace(url.href);"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    file = args.file
    original = file.read_bytes()
    content = original.decode("utf-8")
    if "url.searchParams.set('mgautoconnect', '1')" in content:
        print("ALREADY_PATCHED — no changes")
        return
    if content.count(OLD) != 1:
        sys.exit("STOP: expected exact OWNER viewer fragment not found once; no changes")
    result = content.replace(OLD, NEW)
    if not args.apply:
        print("READY: exact fragment matched; run with --apply to update")
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    backup = file.with_name(file.name + ".bak-mgautoconnect-" + stamp)
    shutil.copy2(file, backup)
    temp = file.with_name("." + file.name + ".mgautoconnect-temp")
    try:
        with temp.open("wb") as fd:
            fd.write(result.encode("utf-8"))
        shutil.copymode(file, temp)
        py_compile.compile(str(temp), doraise=True)
        os.replace(temp, file)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    print("PATCHED:", file)
    print("BACKUP:", backup)
    print("RESTART_REQUIRED: multiser vis-api (restart manually after reviewing output)".replace(" ", ""))

if __name__ == "__main__":
    main()
