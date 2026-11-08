#!/usr/bin/env python3
"""MASTER 1.5: one-shot, ASUS ROG-only Mesh Standard move and verified OWNER confirmation.

Asserts signed STANDARD Windows receipt, actual OWNER edition, unchanged sync revision,
unique exact Mesh node ID, and destination. Attempts one MeshCtrl move and re-reads
MeshCentral independently even if MeshCtrl reports a failure.
No licence mutation, Windows/SCM operation, other device/group change, or fake OK.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
from app.routers import multiguard_license as license
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import Group, validate_groups, observed_group_for_node

def safe_category(exc):
    s=str(exc).lower()
    for label,p in (
        ("AUTHORIZATION",r"access denied|permission|forbidden|insufficient|unauthorized|not allowed"),
        ("AUTHENTICATION",r"invalid login|login failed|authentication|token expired|bad key"),
        ("UNKNOWN_DESTINATION",r"group not found|invalid mesh|unknown group|groupid"),
        ("UNKNOWN_NODE",r"device not found|invalid device|unknown device|devid"),
        ("MESHCTRL_SYNTAX",r"unknown option|invalid command|missing required|usage:"),
        ("NETWORK_TLS",r"ssl|tls|certificate|unable to connect|timed out|timeout|econn"),
        ("OUTPUT_VERIFICATION",r"confirmation|output|response|json"),
    ):
        if re.search(p,s):return label
    return "OTHER"

def read_nodes():
    return sync._list_visible_nodes()

def main():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    pid=int(subprocess.check_output(
        ["systemctl","show","-p","MainPID","--value","multiservis-api.service"],
        text=True).strip())
    if pid<2:raise RuntimeError("FASTAPI_SERVICE_STOPPED")
    for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        if b"=" in pair:
            k,v=pair.split(b"=",1)
            if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
    groups=validate_groups(os.environ)
    with engine.connect() as db:
        rows=db.execute(text("""
            SELECT p.installation_id,p.hostname,p.status AS install_status,
                   l.plan_code,l.lifecycle,s.status,s.attempts,s.revision,
                   s.requested_group,s.target_mesh_id,n.mesh_node_id,
                   t.state AS receipt_state,t.target_mode AS receipt_target
            FROM guard.pending_installations p
            JOIN guard.license_links l ON l.installation_id=p.installation_id
            JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
            JOIN guard.workshop_mesh_nodes n ON n.installation_id=p.installation_id
            JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
            WHERE upper(p.hostname)='ROG'
        """)).mappings().all()
        if len(rows)!=1:raise RuntimeError("ROG_OWNER_NOT_UNIQUE")
        r=rows[0]
        iid=r["installation_id"]
        desired,target=sync._current_owner_target(db,iid)
        if (r["plan_code"]!="multi_guard" or r["lifecycle"]!="ACTIVE"
            or license._owner_effective_entitlement_mode(db,iid)!="CLIENT"
            or desired!="NONE" or target!=groups[Group.STANDARD]
            or r["requested_group"]!="NONE" or r["target_mesh_id"]!=target
            or r["receipt_state"]!="COMPLETED" or r["receipt_target"]!="STANDARD"
            or not sync._verified_standard_shutdown(db,iid)
            or r["status"] not in ("RETRY","WAITING","OK")):
            raise RuntimeError("CURRENT_OWNER_STANDARD_GATE_NOT_VERIFIED")
        if r["status"]=="RETRY" and r["attempts"]!=3:
            raise RuntimeError("RETRY_ATTEMPT_COUNT_CHANGED")
        mesh._auto_mesh_identifier(r["mesh_node_id"],"node")
        revision=r["revision"]
    nodes=read_nodes()
    matched=[n for n in nodes if isinstance(n,dict) and n.get("_id")==r["mesh_node_id"]]
    if len(matched)!=1 or not any(str(matched[0].get(k) or "").strip().upper()=="ROG" for k in ("name","host")):
        raise RuntimeError("ROG_VISIBLE_MESH_NODE_NOT_UNIQUE")
    before=matched[0].get("meshid")
    if before not in (groups[Group.SERVICE],target):
        raise RuntimeError("ROG_IN_UNEXPECTED_MESH_GROUP")
    print("PASS: signed STANDARD receipt, active Standard OWNER, unique ROG node, unchanged expected group")
    print("ROG_MESH_BEFORE:", "SERWIS" if before==groups[Group.SERVICE] else "STANDARD")
    if before!=target:
        # Perform exactly one official MeshCtrl move. The group/node are read
        # from verified OWNER and MeshCentral, never from user text.
        try:
            mesh.move_registered_node_to_group(r["mesh_node_id"],target)
            print("MESH_MOVE_COMMAND: SUCCESS")
        except Exception as e:
            print("MESH_MOVE_COMMAND:",type(e).__name__,"CATEGORY:",safe_category(e))
            # MeshCentral could have completed the move despite an ambiguous
            # acknowledgement. Always read back before deciding whether to fail.
    nodes_after=read_nodes()
    visible,observed=observed_group_for_node(nodes_after,r["mesh_node_id"])
    if not visible or observed!=target:
        print("MESH_MOVE_NOT_CONFIRMED")
        print("STATUS_UNCHANGED:",r["status"],"ATTEMPTS:",r["attempts"])
        print("NO_LICENSE_OR_OTHER_MESH_DEVICE_CHANGED")
        raise RuntimeError("ROG_STILL_NOT_IN_STANDARD_GROUP")
    print("PASS: exact saved ROG Mesh node confirmed in STANDARD")
    # Confirm status in a separate DB transaction only after Mesh readback.
    with engine.begin() as db:
        db.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).one()
        current=db.execute(text("""
            SELECT revision,status,requested_group,target_mesh_id
            FROM guard.owner_mesh_group_sync WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).mappings().one()
        desired_now,target_now=sync._current_owner_target(db,iid)
        if (current["revision"]!=revision or current["requested_group"]!="NONE"
            or current["target_mesh_id"]!=target or desired_now!="NONE" or target_now!=target
            or not sync._verified_standard_shutdown(db,iid)):
            raise RuntimeError("OWNER_CHANGED_DURING_MESH_MOVE_NO_FALSE_OK")
        result=db.execute(text("""
            UPDATE guard.owner_mesh_group_sync
            SET status='OK',observed_mesh_id=:target,confirmed_at=now(),
                last_error=NULL,updated_at=now()
            WHERE installation_id=:iid AND revision=:revision
              AND requested_group='NONE' AND target_mesh_id=:target
        """),{"iid":iid,"revision":revision,"target":target})
        if result.rowcount!=1:raise RuntimeError("SYNC_ROW_CONCURRENTLY_MODIFIED")
    with engine.connect() as db:
        label,status,attempts=sync.get_status(db,iid)
        if (label,status)!=("Standard","Brak zdalnego"):
            raise RuntimeError("OWNER_DISPLAY_POSTCHECK_FAILED")
    print("PASS: OWNER Standard / Brak zdalnego")
    print("PASS: no licence, Windows SCM, channel, other Mesh node, or Lenovo operations")
    print("MASTER15_ASUS_STANDARD_MESH_REPAIR_PASS")

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("MASTER15_ASUS_STANDARD_MESH_REPAIR_STOP",type(exc).__name__,str(exc)[:130],file=sys.stderr)
        raise SystemExit(1)
