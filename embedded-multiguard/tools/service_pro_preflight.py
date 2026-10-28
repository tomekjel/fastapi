#!/usr/bin/env python3
"""Read-only service-PRO deployment prerequisites; never prints credentials."""
from pathlib import Path
import os
import re

ENV = Path("/etc/multiservis/multiguard-panel.env")
KEYS = ("MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID", "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID")
def read_env():
    result = {}
    if ENV.is_file():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            result[key.strip()] = val.strip().strip('"').strip("'")
    return result

def main():
    env = read_env()
    print("SERVICE_PRO PREFLIGHT — READ ONLY")
    ids = {}
    for key in KEYS:
        value = env.get(key, os.environ.get(key, ""))
        valid = bool(re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", value))
        print(f"{key}: {'SET' if valid else 'MISSING_OR_INVALID'}")
        ids[key] = value if valid else None
    if not ids[KEYS[0]]:
        print("BLOCKED: Dedicated service diagnostics group must be configured before unattended access.")
    elif ids[KEYS[0]] == ids[KEYS[1]]:
        print("BLOCKED: Service group must differ from customer single-consent group.")
    else:
        print("CONFIG_READY: Distinct group identifiers configured; live node membership still requires verification.")

if __name__ == "__main__":
    main()
