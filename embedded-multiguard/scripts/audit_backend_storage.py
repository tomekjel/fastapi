#!/usr/bin/env python3
"""Read-only inspection of archive source: no production data, no secrets.

Run on GitHub checkout to identify media storage model required for safe
owner-only photo streaming in the web panel.
"""
from __future__ import annotations
from pathlib import Path
from zipfile import ZipFile
import re

ARCHIVE=Path("MultiServisServer_FINAL.zip")
if not ARCHIVE.exists():
    print("ARCHIVE_MISSING")
    raise SystemExit(0)

tokens=re.compile(
  r"core\.storage_objects|service_order_media|storage_object_id|"
  r"\b(?:media|image|photo|download|file|storage)\b|"
  r"^(?:class|def|async def) ",re.I
)
strong=re.compile(r"core\.storage_objects|service_order_media|storage_object_id|@(?:router|app)\.(?:get|post)\(",re.I)
with ZipFile(ARCHIVE) as z:
    names=[name for name in z.namelist()
           if name.endswith(".py") and not name.startswith("__MACOSX")
           and "venv" not in name.lower() and "site-packages" not in name.lower()]
    print(f"Archive python source files: {len(names)}")
    found=0
    for name in names:
        if not any(t in name.lower() for t in ("router", "storage", "media", "models", "service", "main", "database")):
            continue
        b=z.read(name)
        if len(b)>400000:
            continue
        lines=b.decode("utf-8","replace").splitlines()
        hits=[i for i,x in enumerate(lines) if strong.search(x)]
        if not hits:
            continue
        found+=1
        print("SOURCE",name)
        limit=0
        for i in hits:
            if limit>=35: break
            lo=max(0,i-2);hi=min(len(lines),i+3)
            for j in range(lo,hi):
                txt=lines[j].strip()
                # Keep only structural info, never values: omit credentials/SQL literal params
                if re.search(r"password|secret|token|PRIVATE.KEY|credentials",txt,re.I):
                    continue
                if len(txt)>190: txt=txt[:190]+"..."
                print(f" {j+1}: {txt}")
            limit+=1
    print("CANDIDATE_SOURCE_FILES",found)

    media_router=next((n for n in names if n.endswith("/app/routers/receptions.py")),None)
    if media_router:
        print("FOCUSED_MEDIA_READ_IMPLEMENTATION")
        lines=z.read(media_router).decode("utf-8","replace").splitlines()
        for k in range(650,min(701,len(lines))):
            line=lines[k].strip()
            if re.search(r"password|secret|token|PRIVATE.KEY|credentials",line,re.I):
                continue
            print(f"{k+1}: {line[:210]}")
        print("FOCUSED_STORAGE_ROOT_IMPORTS")
        for k,line in enumerate(lines[:38]):
            if "settings" in line or "FileResponse" in line or "Path" in line:
                print(f"{k+1}: {line.strip()[:210]}")

    schema_files=[n for n in z.namelist() if n.lower().endswith((".sql",".yml",".yaml","requirements.txt")) and not n.startswith("__MACOSX")]
    print("BUNDLED_SCHEMA_AND_SETUP_PATHS",schema_files[:80])
    for item in schema_files:
        if item.endswith("requirements.txt"):
            print("REQUIREMENTS_SOURCE",item)
            print("REQUIREMENTS_PACKAGES",[
                line.split("==")[0].strip() for line in z.read(item).decode("utf-8","replace").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ])
