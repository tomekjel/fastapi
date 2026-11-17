#!/usr/bin/env python3
"""Read-only MASTER110 inspection of configured Multi-Guard acceptance docs.

No network access, database, service restart, config changes or secret output.
Run on LXC 103 with MULTIGUARD_CONFIG_FILE (or its usual default).
"""
import hashlib
import json
import os
from pathlib import Path

PATH=Path(os.environ.get("MULTIGUARD_CONFIG_FILE","/opt/multiservis/config/multiguard-license.json"))
def check():
    # Environment overrides local JSON in current FastAPI _setting().
    raw=os.environ.get("MULTIGUARD_REQUIRED_DOCUMENTS")
    if raw:
        origin="environment"
        try:
            docs=json.loads(raw)
        except json.JSONDecodeError:
            raise SystemExit("STOP: invalid MULTIGUARD_REQUIRED_DOCUMENTS environment JSON")
    else:
        origin="config"
        if not PATH.is_file():
            raise SystemExit("STOP: config file does not exist (no live changes made)")
        config=json.loads(PATH.read_text(encoding="utf-8"))
        docs=config.get("MULTIGUARD_REQUIRED_DOCUMENTS",[])
        if isinstance(docs,str):
            docs=json.loads(docs)
    if not isinstance(docs,list):
        raise SystemExit("STOP: configured policy set is not a list")
    print("CONFIG_SOURCE:",origin)
    print("DOCUMENT_COUNT:",len(docs))
    kinds=[]
    for item in docs:
        if not isinstance(item,dict):
            raise SystemExit("STOP: invalid document object")
        kind=str(item.get("kind",""))
        version=str(item.get("version",""))
        body=item.get("content_markdown","")
        if not isinstance(body,str) or not body:
            raise SystemExit("STOP: document content missing: "+kind)
        print("KIND:",kind,"VERSION:",version,"SHA256:",hashlib.sha256(body.encode("utf-8")).hexdigest())
        kinds.append(kind)
    if kinds != ["remote_policy","browser_shield"]:
        raise SystemExit("STOP: live configuration is not the two approved policy kinds in order; deployment required")
    print("PASS: exactly two correctly named policy documents configured (compare SHA256 with installer before deployment)")
if __name__=="__main__":
    check()
