"""Run explicitly against a disposable DB named remote_transport_test.

Real transactions/constraints; authentication and MeshCtrl are test doubles.
No production credentials or data. Requires OWNER_TRANSPORT_TEST_DB.
"""
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import test_session_transport_enrollment as offline
from sqlalchemy import create_engine, text

paid, workshop, mesh = offline.paid, offline.workshop, offline.mesh


class TransportPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        url=os.environ["OWNER_TRANSPORT_TEST_DB"]
        cls.engine=create_engine(url)
        if cls.engine.url.database != "remote_transport_test":
            raise RuntimeError("Only a disposable remote_transport_test database is permitted")
        with cls.engine.begin() as db:
            for sql in (
                "CREATE SCHEMA IF NOT EXISTS guard",
                """CREATE TABLE IF NOT EXISTS guard.installations (
                    id uuid PRIMARY KEY,installation_external_id uuid UNIQUE,
                    service_device_id uuid,plan_code text,lifecycle text,valid_until timestamptz,
                    is_current boolean DEFAULT true,mesh_node_id text UNIQUE)""",
                """CREATE TABLE IF NOT EXISTS guard.remote_sessions (
                    id uuid PRIMARY KEY,installation_id uuid,status text,expires_at timestamptz,
                    consented_at timestamptz,ended_at timestamptz,granted_capabilities jsonb,mesh_public_id text)""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_mesh_nodes (
                    installation_id uuid PRIMARY KEY,mesh_node_id text UNIQUE,updated_at timestamptz DEFAULT now())""",
                """CREATE TABLE IF NOT EXISTS guard.pending_installations (
                    installation_id uuid PRIMARY KEY,status text)""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_grants (
                    installation_id uuid PRIMARY KEY,edition text,enabled boolean)""",
                "CREATE TABLE IF NOT EXISTS guard.workshop_remote_sessions (LIKE guard.remote_sessions INCLUDING ALL)",
            ): db.execute(text(sql))

    def setUp(self):
        self.external,self.internal,self.sid=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
        self.node="node//"+(self.sid.hex*2)
        self.auth=dict(requestId="test-request-123",nonce="test-nonce-123",sentAt=datetime.now(timezone.utc),
            installationId=self.external,deviceId="test-device-123456789",sessionId=self.sid,meshNodeId=self.node[6:])
        with self.engine.begin() as db:
            db.execute(text("""INSERT INTO guard.installations(id,installation_external_id,service_device_id,plan_code,lifecycle)
                VALUES (:id,:ext,:dev,'PRO','ACTIVE')"""),dict(id=self.internal,ext=self.external,dev=uuid.uuid4()))
            db.execute(text("""INSERT INTO guard.remote_sessions(id,installation_id,status,expires_at,consented_at,granted_capabilities)
                VALUES (:sid,:id,'CONSENTED',:expiry,now(),'["desktop"]')"""),
                dict(sid=self.sid,id=self.internal,expiry=datetime.now(timezone.utc)+timedelta(minutes=5)))

    def authenticate(self, db, external, device, credential):
        return db.execute(text("SELECT * FROM guard.installations WHERE installation_external_id=:ext"),{"ext":external}).mappings().first()

    def test_paid_maps_internal_id_and_rolls_back_if_audit_fails(self):
        body=paid.AgentSessionMeshBody(**self.auth,installationCredential="x"*32)
        with patch.object(workshop,"_schema"), patch.object(paid,"engine",self.engine), \
             patch.object(paid,"_require_agent",side_effect=self.authenticate), \
             patch.object(paid,"_plan_change_pending",return_value=False), \
             patch.object(mesh,"verify_session_node",return_value=self.node), \
             patch.object(paid,"_audit",side_effect=RuntimeError("synthetic audit failure")):
            with self.assertRaises(RuntimeError): paid.agent_session_mesh_enroll(body)
        with self.engine.connect() as db:
            self.assertIsNone(db.execute(text("SELECT mesh_node_id FROM guard.installations WHERE id=:id"),{"id":self.internal}).scalar_one())
        with patch.object(workshop,"_schema"), patch.object(paid,"engine",self.engine), \
             patch.object(paid,"_require_agent",side_effect=self.authenticate), \
             patch.object(paid,"_plan_change_pending",return_value=False), \
             patch.object(mesh,"verify_session_node",return_value=self.node), patch.object(paid,"_audit"):
            self.assertTrue(paid.agent_session_mesh_enroll(body)["accepted"])
        with self.engine.connect() as db:
            self.assertEqual(db.execute(text("SELECT mesh_node_id FROM guard.installations WHERE id=:id"),{"id":self.internal}).scalar_one(),self.node)

    def test_workshop_uses_real_grant_and_session(self):
        with self.engine.begin() as db:
            db.execute(text("INSERT INTO guard.pending_installations VALUES (:iid,'WAITING')"),{"iid":self.external})
            db.execute(text("INSERT INTO guard.workshop_grants VALUES (:iid,'PRO',true)"),{"iid":self.external})
            db.execute(text("""INSERT INTO guard.workshop_remote_sessions(id,installation_id,status,expires_at,consented_at,granted_capabilities)
                VALUES (:sid,:iid,'CONSENTED',:expiry,now(),'["desktop"]')"""),
                {"sid":self.sid,"iid":self.external,"expiry":datetime.now(timezone.utc)+timedelta(minutes=5)})
        body=workshop.WorkshopSessionMeshEnrollment(**self.auth,discoveryCredential="x"*32)
        with patch.object(workshop,"_schema"),patch.object(workshop,"_authenticate"), \
             patch.object(workshop,"engine",self.engine),patch.object(mesh,"verify_session_node",return_value=self.node), \
             patch.object(workshop,"_event"):
            self.assertTrue(workshop.workshop_session_mesh_enroll(body)["accepted"])
        with self.engine.connect() as db:
            self.assertEqual(db.execute(text("SELECT mesh_node_id FROM guard.workshop_mesh_nodes WHERE installation_id=:id"),{"id":self.external}).scalar_one(),self.node)

    @classmethod
    def tearDownClass(cls): cls.engine.dispose()

if __name__=="__main__": unittest.main()
