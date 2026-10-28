#!/usr/bin/env python3
"""Read-only MeshCentral group discovery for MultiGuard deployment.

Uses the already configured MeshCtrl service token. Does not print credentials
or modify groups, agents, grants or database state.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as mesh

NAMES = ("MultiGuard PRO - Serwis", "MultiGuard PRO - Klient")


def main():
    command = list(mesh._base_command())
    command[command.index("DeviceSharing")] = "ListDeviceGroups"
    try:
        output = mesh._run(command + ["--json"])
        data = json.loads(output)
    except (mesh.MeshCentralError, ValueError) as exc:
        print("BLOCKED: MeshCentral group inventory not available (no changes made).")
        return 2

    found = {}
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            name = item.get("name")
            gid = item.get("_id", item.get("id"))
            if name in NAMES and isinstance(gid, str) and gid.startswith("mesh/"):
                found.setdefault(name, set()).add(gid)
            for value in item.values():
                if isinstance(value, (dict, list)):
                    stack.append(value)

    for name in NAMES:
        matches = sorted(found.get(name, ()))
        print(f"{name}: {matches[0] if len(matches) == 1 else 'MISSING_OR_AMBIGUOUS'}")
    if any(len(found.get(name, ())) != 1 for name in NAMES):
        print("BLOCKED: Both exact group identities must be resolved before deployment.")
        return 2
    if found[NAMES[0]] == found[NAMES[1]]:
        print("BLOCKED: Service and client groups must be distinct.")
        return 2
    print("PASS: Exact, distinct group identifiers discovered; not configured yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
