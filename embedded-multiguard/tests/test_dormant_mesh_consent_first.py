"""Offline regression: a dormant Standard->Pro device may receive a consent request
before MeshAgent is registered, but cannot be connected until a VERIFIED node
is attached. No DB queries, MeshCtrl commands, or user sessions are executed.
"""
from __future__ import annotations

import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from types import ModuleType

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# This repository's embedded router code is mounted inside the deployed
# FastAPI app. Mock host-only services here to make tests genuinely offline.
database=ModuleType("app.database")
database.engine=MagicMock()
security=ModuleType("app.security")
security.CurrentUser=object
security.require_owner=lambda: None
runtime=ModuleType("app.routers.multiguard_runtime")
runtime._ensure_schema=lambda: None
runtime._require_agent=lambda *args,**kwargs: None
mesh=ModuleType("app.routers.multiguard_meshcentral")
mesh.MeshCentralError=type("MeshCentralError",(Exception,),{})
mesh.create_share=MagicMock()
mesh.revoke_share=MagicMock()
mesh.verify_registered_node=MagicMock()
license=ModuleType("app.routers.multiguard_license")
license._panel_auth=lambda: None
license._panel_html=lambda *args,**kwargs: ""
for name,mod in (
    ("app.database",database), ("app.security",security),
    ("app.routers.multiguard_runtime",runtime),
    ("app.routers.multiguard_meshcentral",mesh),
    ("app.routers.multiguard_license",license),
):
    sys.modules.setdefault(name,mod)
from app.routers import multiguard_workshop_remote as workshop
from app.routers import multiguard_remote as commercial


class DormantAgentConsentFirstTests(unittest.TestCase):
    def test_workshop_can_request_consent_without_a_mesh_node(self):
        iid = uuid.uuid4()
        db = MagicMock()
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value={
                 "edition": "PRO", "enabled": True, "mesh_node_id": None
             }), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(workshop, "_open", return_value=None), \
             patch.object(workshop, "_event") as event:
            engine.begin.return_value.__enter__.return_value = db
            sid = workshop.request_consent_for_owner(iid)
            self.assertIsInstance(sid, uuid.UUID)
            db.execute.assert_called_once()
            sql, params = db.execute.call_args.args
            self.assertIn("INSERT INTO guard.workshop_remote_sessions", str(sql))
            self.assertEqual(params["iid"], iid)
            event.assert_called_once()

    def test_workshop_request_does_not_bypass_pro_entitlement(self):
        iid = uuid.uuid4()
        db = MagicMock()
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value=None), \
             patch.object(workshop, "_eligible", return_value=False):
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(Exception) as rejected:
                workshop.request_consent_for_owner(iid)
            self.assertEqual(rejected.exception.status_code, 403)
            db.execute.assert_not_called()

    def test_no_second_workshop_request_when_previous_is_active(self):
        iid = uuid.uuid4()
        db = MagicMock()
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value={"edition": "PRO", "enabled": True}), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(workshop, "_open", return_value={"status": "REQUESTED"}):
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(Exception) as rejected:
                workshop.request_consent_for_owner(iid)
            self.assertEqual(rejected.exception.status_code, 409)
            db.execute.assert_not_called()

    def test_workshop_cannot_connect_without_verified_mesh_identity(self):
        sid = uuid.uuid4()
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value = {
            "id": sid,
            "installation_id": uuid.uuid4(),
            "status": "CONSENTED",
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            "granted_capabilities": ["desktop"],
            "mesh_public_id": None,
        }
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value={
                 "edition": "PRO", "enabled": True, "mesh_node_id": None
             }), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(workshop.meshcentral, "create_share") as share:
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException) as caught:
                workshop.connect_for_owner(sid)
            self.assertEqual(caught.exception.status_code, 409)
            share.assert_not_called()

    def test_paid_pro_can_request_consent_before_mesh_registration(self):
        install = uuid.uuid4()
        srid = uuid.uuid4()
        body = commercial.OwnerRemoteCreateBody(supportRequestId=srid)
        db = MagicMock()
        support = {
            "id": srid, "installation_id": install,
            "service_device_id": uuid.uuid4(), "subject": "Test",
            "mesh_node_id": None, "plan_code": "multi_guard_pro",
            "lifecycle": "ACTIVE", "valid_until": None,
            "is_current": True, "support_status": "OPEN",
        }
        db.execute.return_value.mappings.return_value.first.side_effect = [
            support, {"status": "REQUESTED"}
        ]
        with patch.object(commercial, "_ensure_schema"), \
             patch.object(commercial, "engine") as engine, \
             patch.object(commercial, "_owner_label", return_value=(uuid.uuid4(), "OWNER")), \
             patch.object(commercial, "_has_active_remote_pro", return_value=True), \
             patch.object(commercial, "_plan_change_pending", return_value=False), \
             patch.object(commercial, "_expire_and_find_open", return_value=None), \
             patch.object(commercial, "_audit") as audit, \
             patch.object(commercial, "_remote_public", return_value={"status": "REQUESTED"}):
            engine.begin.return_value.__enter__.return_value = db
            result = commercial.create_remote_session(body, user=MagicMock())
            self.assertEqual(result["status"], "REQUESTED")
            self.assertEqual(db.execute.call_count, 4)
            audit.assert_called_once()

    def test_paid_pro_cannot_connect_without_verified_mesh_identity(self):
        sid = uuid.uuid4()
        row = {
            "id": sid, "installation_id": uuid.uuid4(), "status": "CONSENTED",
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            "mesh_node_id": None, "granted_capabilities": ["desktop"],
        }
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value = row
        with patch.object(commercial, "_ensure_schema"), \
             patch.object(commercial, "engine") as engine, \
             patch.object(commercial, "_owner_label", return_value=(uuid.uuid4(), "OWNER")), \
             patch.object(commercial, "_has_active_remote_pro", return_value=True), \
             patch.object(commercial, "_plan_change_pending", return_value=False), \
             patch.object(commercial.meshcentral, "create_share") as share:
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException) as caught:
                commercial.remote_session_connect(str(sid), user=MagicMock())
            self.assertEqual(caught.exception.status_code, 409)
            share.assert_not_called()


if __name__ == "__main__":
    unittest.main()
