#!/usr/bin/env python3
"""One consolidated, read-only diagnosis for ASUS-only MeshCentral sync failure."""
import inspect,json,os,re,subprocess,sys
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import validate_groups,Group

def main():
 print("=== MASTER15 FINAL BATCH DIAGNOSIS / READ ONLY ===")
 pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
 if pid<2:raise RuntimeError("FASTAPI_STOPPED")
 for entry in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
  if b"=" in entry:
   k,v=entry.split(b"=",1)
   if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
 groups=validate_groups(os.environ)
 with engine.connect() as db:
  rows=db.execute(text("""
   SELECT p.installation_id,s.status,s.attempts,s.revision,s.requested_group,s.target_mesh_id,
          n.mesh_node_id,t.state receipt,t.target_mode
   FROM guard.pending_installations p JOIN guard.owner_mesh_group_sync s USING (installation_id)
   LEFT JOIN guard.workshop_mesh_nodes n USING (installation_id)
   LEFT JOIN guard.workshop_profile_transitions t USING (installation_id)
   WHERE upper(p.hostname)='ROG'
  """)).mappings().all()
  if len(rows)!=1:raise RuntimeError("ASUS_IDENTITY_NOT_UNIQUE")
  row=rows[0]; iid=row["installation_id"]
  desired,target=sync._current_owner_target(db,iid)
  ack=sync._verified_standard_shutdown(db,iid)
  print("OWNER_REQUESTED",row["requested_group"],"CURRENT",desired,"MATCH",target==row["target_mesh_id"])
  print("RECEIPT",row["receipt"],row["target_mode"],"STANDARD_GATE",ack)
  print("SYNC",row["status"],"ATTEMPTS",row["attempts"],"REVISION",row["revision"])
  print("SAVED_NODE_PRESENT",bool(row["mesh_node_id"]))
  if not (desired=="NONE" and target==groups[Group.STANDARD] and ack):raise RuntimeError("STANDARD_AUTHORIZATION_NOT_VERIFIED")
 cmd=mesh._base_command()
 if cmd.count("DeviceSharing")!=1:raise RuntimeError("UNEXPECTED_MESH_CLI")
 pos=cmd.index("DeviceSharing")
 def read(action):
  return json.loads(mesh._run(cmd[:pos]+[action]+cmd[pos+1:]+["--json"]))
 devices=read("ListDevices")
 target_nodes=[n for n in devices if isinstance(n,dict) and n.get("_id")==row["mesh_node_id"]]
 print("VISIBLE_NODES",len(devices),"EXACT_SAVED_NODE_MATCHES",len(target_nodes))
 if len(target_nodes)!=1:raise RuntimeError("SAVED_NODE_NOT_UNIQUE_OR_VISIBLE")
 node=target_nodes[0]
 print("NODE_IN_SERVICE",node.get("meshid")==groups[Group.SERVICE])
 print("NODE_IN_STANDARD",node.get("meshid")==groups[Group.STANDARD])
 print("ROG_NAME_MATCH",str(node.get("name") or node.get("host") or "").upper()=="ROG")
 try:
  g=read("ListDeviceGroups")
  if isinstance(g,list):
   ids=[x.get("_id") or x.get("meshid") for x in g if isinstance(x,dict)]
   print("STANDARD_GROUP_VISIBLE",groups[Group.STANDARD] in ids)
   print("SERVICE_GROUP_VISIBLE",groups[Group.SERVICE] in ids)
  else:print("GROUPS_FORMAT",type(g).__name__)
 except Exception as e:print("GROUPS_LIST_ERROR",type(e).__name__)
 fn=getattr(mesh,"move_registered_node_to_group",None)
 print("MOVE_HELPER_AVAILABLE",callable(fn))
 if callable(fn):
  code=inspect.getsource(fn)
  # report only syntax literals, never raw command values or credentials
  print("MOVE_HELPER_SOURCE_LINE_COUNT",len(code.splitlines()))
  print("MOVE_HELPER_USES_CLI",("MoveToDeviceGroup" in code))
  print("MOVE_HELPER_ARGS",sorted(set(re.findall(r"""["'](--[A-Za-z-]+)["']""",code))))
  print("MOVE_HELPER_LOGIC",[(x.strip()[:125]) for x in code.splitlines()
     if any(y in x for y in ("MoveToDeviceGroup","--id","--group","_run(","_base_command","return","raise"))][:18])
 print("=== INSTALLED MESHCTRL MOVE HELP (NO MOVE) ===")
 # Help is local and does not send credentials; no authentication needed
 help_args=cmd[:pos]+["Help","MoveToDeviceGroup"]
 try:
  h=subprocess.run(help_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15,check=False)
  print("MESHCTRL_HELP_EXIT",h.returncode)
  for line in (h.stdout+"\n"+h.stderr).splitlines():
   lower=line.lower()
   if any(z in lower for z in ("password","login","token","secret","key","cookie")):continue
   if any(z in lower for z in ("movetodevicegroup","--id","--group","usage","device","move","error","not supported")):
    print("HELP",line[:180])
 except Exception as e:print("MESHCTRL_HELP_ERROR",type(e).__name__)
 try:
  ui=read("UserInfo")
  if isinstance(ui,dict):
   print("MESH_ACCOUNT_ADMIN_FLAGS",{k:ui[k] for k in ("siteadmin","siteAdmin") if k in ui and isinstance(ui[k],int)})
 except Exception as e:print("USER_INFO_ERROR",type(e).__name__)
 print("BATCH_DIAG_COMPLETE / NO_MUTATIONS")

if __name__=="__main__":
 try:main()
 except Exception as e:
  print("BATCH_DIAG_STOP",type(e).__name__,str(e)[:140],file=sys.stderr)
  raise SystemExit(1)
