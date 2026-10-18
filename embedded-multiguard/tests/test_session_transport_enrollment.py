"""Offline protocol regression: mocked SQL/MeshCtrl, real handler decisions."""
import importlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for name in ("app.database", "app.security", "app.routers.multiguard_runtime", "app.routers.multiguard_license"):
    module = ModuleType(name)
    if name.endswith("database"): module.engine = MagicMock()
    if name.endswith("security"):
        module.CurrentUser = object
        module.require_owner = lambda: None
    if name.endswith("runtime"):
        module._ensure_schema = lambda: None
        module._require_agent = MagicMock()
    if name.endswith("license"):
        module._panel_auth = lambda: None
        module._panel_html = lambda *args, **kwargs: ""
    sys.modules.setdefault(name, module)
from fastapi import HTTPException
from app.routers import multiguard_remote as paid
from app.routers import multiguard_workshop_remote as workshop
from app.routers import multiguard_meshcentral as mesh


class SessionTransportTests(unittest.TestCase):
    def setUp(self):
        self.iid, self.sid = uuid.uuid4(), uuid.uuid4()
        self.node = "node//" + "A"*64
        self.group = "mesh//" + "B"*64
        self.row = dict(id=self.sid, installation_id=self.iid, status="CONSENTED",
            expires_at=datetime.now(timezone.utc)+timedelta(minutes=5),
            consented_at=datetime.now(timezone.utc), granted_capabilities=["desktop"],
            ended_at=None, mesh_public_id=None)

    def record(self, **overrides):
        return {"_id":self.node, "meshid":self.group,
                "name":f"MultiGuard-{self.sid}","conn":1, **overrides}

    def verify(self, records):
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": self.group}), \
             patch.object(mesh, "_base_command", return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(mesh, "_run", return_value=json.dumps(records)):
            return mesh.verify_session_node("A"*64, str(self.sid))

    def test_exact_online_node_group_and_session_marker_required(self):
        self.assertEqual(self.verify([self.record()]), self.node)
        for wrong in (self.record(meshid="mesh//"+"C"*64),
                      self.record(name="ASUS"), self.record(name=f"MultiGuard-{uuid.uuid4()}"),
                      self.record(conn=0), self.record(conn=True), self.record(conn="1"),
                      self.record(_id="node//"+"D"*64)):
            with self.subTest(wrong=wrong), self.assertRaises(mesh.MeshCentralError):
                self.verify([wrong])
        with self.assertRaises(mesh.MeshCentralError): self.verify([self.record(),self.record()])

    def test_missing_group_is_not_guessed(self):
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID":""}), \
             patch.object(mesh, "_run") as run, self.assertRaises(mesh.MeshCentralError):
            mesh.verify_session_node("A"*64,str(self.sid))
        run.assert_not_called()

    def test_session_gate_rejects_expiry_denial_wrong_installation_and_existing_share(self):
        now=datetime.now(timezone.utc)
        paid._require_transport_consent(self.row,self.iid,now)
        for change in ({"status":"REQUESTED"},{"status":"DENIED"},
                       {"installation_id":uuid.uuid4()}, {"expires_at":now},
                       {"ended_at":now}, {"consented_at":None},
                       {"granted_capabilities":[]}, {"mesh_public_id":"existing"}):
            with self.subTest(change=change), self.assertRaises(HTTPException):
                paid._require_transport_consent({**self.row,**change},self.iid,now)

    def auth(self):
        return dict(requestId="test-request-id",nonce="test-nonce-id",
                    sentAt=datetime.now(timezone.utc),installationId=self.iid,
                    deviceId="test-device-123456789",sessionId=self.sid,meshNodeId="A"*64)

    def test_commercial_registration_and_recheck_before_write(self):
        body=paid.AgentSessionMeshBody(**self.auth(),installationCredential="x"*32)
        db=MagicMock()
        db.execute.return_value.first.return_value=None
        internal_id=uuid.uuid4()
        self.row["installation_id"]=internal_id
        install={"id":internal_id,"service_device_id":uuid.uuid4(),"mesh_node_id":None}
        db.execute.return_value.mappings.return_value.first.side_effect=[install,self.row,install,self.row]
        with patch.object(workshop,"_schema"), patch.object(paid,"engine") as engine, \
             patch.object(paid,"_require_agent",return_value=install), \
             patch.object(paid,"_has_active_remote_pro",return_value=True), \
             patch.object(paid,"_plan_change_pending",return_value=False), \
             patch.object(mesh,"verify_session_node",return_value=self.node), \
             patch.object(paid,"_audit"):
            engine.connect.return_value.__enter__.return_value=db
            engine.begin.return_value.__enter__.return_value=db
            reply=paid.agent_session_mesh_enroll(body)
            self.assertEqual(reply,{"requestId":body.requestId,"sessionId":str(self.sid),"accepted":True})
            self.assertTrue(any("UPDATE guard.installations" in str(c.args[0]) for c in db.execute.call_args_list))
            writes=[c for c in db.execute.call_args_list if "UPDATE guard.installations" in str(c.args[0])]
            self.assertEqual(writes[0].args[1]["iid"],internal_id)
            db.reset_mock()
            db.execute.return_value.mappings.return_value.first.side_effect=[install,self.row,install,{**self.row,"status":"DENIED"}]
            with self.assertRaises(HTTPException): paid.agent_session_mesh_enroll(body)
            self.assertFalse(any("UPDATE guard.installations" in str(c.args[0]) for c in db.execute.call_args_list))

    def test_workshop_registration_and_rejection_of_foreign_existing_agent(self):
        body=workshop.WorkshopSessionMeshEnrollment(**self.auth(),discoveryCredential="x"*32)
        db=MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value=self.row
        db.execute.return_value.first.return_value=None
        grant={"mesh_node_id":None}
        with patch.object(workshop,"_schema"), patch.object(workshop,"_authenticate"), \
             patch.object(workshop,"engine") as engine, \
             patch.object(workshop,"_eligible",return_value=True), \
             patch.object(workshop,"_grant",return_value=grant), \
             patch.object(mesh,"verify_session_node",return_value=self.node), patch.object(workshop,"_event"):
            engine.connect.return_value.__enter__.return_value=db
            engine.begin.return_value.__enter__.return_value=db
            self.assertTrue(workshop.workshop_session_mesh_enroll(body)["accepted"])
            db.reset_mock()
            grant["mesh_node_id"]="node//"+"C"*64
            with self.assertRaises(HTTPException): workshop.workshop_session_mesh_enroll(body)
            self.assertFalse(any("INSERT INTO guard.workshop_mesh_nodes" in str(c.args[0]) for c in db.execute.call_args_list))

    def test_workshop_consent_refreshes_enrollment_deadline(self):
        # Consent near the end of the original request must still allow agent enrollment.
        body = workshop.WorkshopDecision(**self.auth(), discoveryCredential="x"*32,
                                         allowDesktop=True)
        old_expiry = datetime.now(timezone.utc) + timedelta(seconds=2)
        pending = {**self.row, "status":"REQUESTED", "expires_at":old_expiry}
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value = pending
        db.execute.return_value.mappings.return_value.one.return_value = {
            **pending, "status":"CONSENTED"}
        with patch.object(workshop, "_schema"), patch.object(workshop, "_authenticate"), \
             patch.object(workshop, "_grant", return_value={"edition":"PRO","enabled":True,"status":"NEW"}), \
             patch.object(workshop, "engine") as engine, patch.object(workshop, "_event"):
            engine.begin.return_value.__enter__.return_value = db
            workshop.workshop_remote_decision(body)
        writes = [c for c in db.execute.call_args_list
                  if "SET status='CONSENTED'" in str(c.args[0])]
        self.assertEqual(len(writes), 1)
        params = writes[0].args[1]
        self.assertIn("expires_at=:consent_expires", str(writes[0].args[0]))
        self.assertGreater(params["consent_expires"], old_expiry + timedelta(minutes=4))

    def test_active_snapshot_uses_actual_share_expiry(self):
        row={**self.row,"status":"CONNECT_READY", "support_request_id":self.sid,
             "requested_by_name":"OWNER","subject":"Test", "requested_capabilities":["desktop"],
             "requested_at":datetime.now(timezone.utc),"connected_at":None,"reconnect_until":None,
             "mesh_share_expires_at":datetime.now(timezone.utc)+timedelta(minutes=60),"last_error":None}
        for renderer in (paid._remote_public,workshop._public):
            self.assertEqual(renderer(row)["expiresAt"],row["mesh_share_expires_at"].isoformat())

    def test_old_online_agent_never_satisfies_new_session(self):
        old = self.record(name=f"MultiGuard-{uuid.uuid4()}")
        for connected in (0, 1):
            with self.assertRaises(mesh.MeshCentralError):
                self.verify([{**old, "conn": connected}])
        self.assertEqual(self.verify([self.record()]), self.node)

    def test_readiness_is_bound_to_current_session(self):
        grant = {"mesh_node_id": self.node, "mesh_session_id": uuid.uuid4()}
        self.assertFalse(workshop.session_node_ready(grant, self.row))
        grant["mesh_session_id"] = self.sid
        self.assertTrue(workshop.session_node_ready(grant, self.row))
        grant["mesh_node_id"] = None
        self.assertFalse(workshop.session_node_ready(grant, self.row))

    def test_rotation_requires_ended_owned_session_without_share(self):
        ended = {**self.row, "status": "ENDED", "ended_at": datetime.now(timezone.utc)}
        self.assertTrue(workshop._can_replace_session_node(ended, self.iid))
        for previous in (None, self.row, {**ended, "ended_at": None},
                         {**ended, "mesh_public_id": "still-live"},
                         {**ended, "installation_id": uuid.uuid4()}):
            self.assertFalse(workshop._can_replace_session_node(previous, self.iid))

    def test_workshop_end_during_mesh_verification_prevents_binding(self):
        body = workshop.WorkshopSessionMeshEnrollment(**self.auth(), discoveryCredential="x"*32)
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.side_effect = [
            self.row, {**self.row, "status": "ENDED", "ended_at": datetime.now(timezone.utc)}]
        with patch.object(workshop, "_schema"), patch.object(workshop, "_authenticate"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(workshop, "_grant", return_value={"mesh_node_id": None}), \
             patch.object(mesh, "verify_session_node", return_value=self.node):
            engine.connect.return_value.__enter__.return_value = db
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException): workshop.workshop_session_mesh_enroll(body)
        self.assertFalse(any("INSERT INTO guard.workshop_mesh_nodes" in str(c.args[0])
                             for c in db.execute.call_args_list))

if __name__ == "__main__": unittest.main()
