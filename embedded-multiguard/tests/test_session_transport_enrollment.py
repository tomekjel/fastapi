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

    def test_meshctrl_text_status_fallback_contract(self):
        import inspect
        source = inspect.getsource(mesh.verify_session_node)
        self.assertIn("csv.reader(listing.splitlines(), skipinitialspace=True)", source)
        self.assertIn("fields[0].strip() != local_id", source)
        self.assertIn("fields[1].strip() != name", source)
        self.assertIn("if len(statuses) != 1:", source)
        self.assertIn("not (connected & 1)", source)

    def test_meshctrl_fallback_real_behavior(self):
        record = self.record()
        del record["conn"]
        label = f"MultiGuard-{self.sid}"
        def check(lines):
            with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": self.group}), \
                 patch.object(mesh, "_base_command", return_value=["meshctrl", "DeviceSharing"]), \
                 patch.object(mesh, "_run", side_effect=[json.dumps([record]), lines]):
                return mesh.verify_session_node("A"*64, str(self.sid))
        live = f'A'*64 + f', "{label}", 2, 1, 0\n'
        self.assertEqual(check(live), self.node)
        for lines in (
            f'A'*64 + f', "{label}", 2, 0, 0\n',
            f'A'*64 + f', "{label}", 2, 2, 0\n',
            f'B'*64 + f', "{label}", 2, 1, 0\n',
            f'A'*64 + ', "Foreign", 2, 1, 0\n',
            live + live,
            "",
        ):
            with self.subTest(lines=lines[:16]), self.assertRaises(mesh.MeshCentralError):
                check(lines)

    def test_local_standing_opt_in_requires_explicit_user_action_and_exact_owner_receipt(self):
        now=datetime.now(timezone.utc)
        req=workshop.WorkshopStandingAttestation(
            requestId=str(uuid.uuid4()),nonce=str(uuid.uuid4()),sentAt=now,
            installationId=self.iid,deviceId="d"*32,
            discoveryCredential="c"*64,explicitConsent=True,
            acknowledgedConsentSha256="a"*64,
        )
        # Pydantic must reject an absent or false interactive confirmation.
        with self.assertRaises(Exception):
            workshop.WorkshopStandingAttestation(
                requestId=req.requestId,nonce=req.nonce,sentAt=now,
                installationId=self.iid,deviceId=req.deviceId,
                discoveryCredential=req.discoveryCredential,
                explicitConsent=False,acknowledgedConsentSha256="a"*64)
        grant={"status":"WAITING","edition":"PRO","enabled":True,
               "mesh_node_id":self.node}
        valid={
            "approved_mesh_node_id":self.node,"device_scope":"CLIENT_DIAGNOSTIC",
            "owner_approved_at":now,"local_opt_in_attested_at":None,
            "prior_consent_sha256":"a"*64,"revoked_at":None,
        }
        def check(record, grant_value=grant, expected=None):
            db=MagicMock()
            statements=[]
            def execute(statement,params=None):
                sql=str(statement);statements.append(sql)
                result=MagicMock()
                if "FROM guard.workshop_standing_remote_authorizations" in sql:
                    result.mappings.return_value.first.return_value=record
                return result
            db.execute.side_effect=execute
            with patch.object(workshop,"_schema"), patch.object(workshop,"_authenticate") as auth, \
                 patch.object(workshop,"engine") as engine, \
                 patch.object(workshop,"_grant",return_value=grant_value):
                engine.begin.return_value.__enter__.return_value=db
                if expected is not None:
                    with self.assertRaises(HTTPException) as caught:
                        workshop.workshop_standing_attest(req)
                    self.assertEqual(caught.exception.status_code,expected)
                else:
                    result=workshop.workshop_standing_attest(req)
                    self.assertEqual(result,{"requestId":req.requestId,
                        "localOptInAttested":True,"unattendedReady":False})
                auth.assert_called_once_with(req)
            return statements
        statements=check(valid)
        self.assertTrue(any("local_opt_in_attested_at=:now" in x for x in statements))
        self.assertTrue(any("'LOCAL_OPT_IN_ATTESTED'" in x for x in statements))
        for record in (
            None,
            {**valid,"owner_approved_at":None},
            {**valid,"revoked_at":now},
            {**valid,"approved_mesh_node_id":"node//"+"B"*64},
            {**valid,"prior_consent_sha256":"b"*64},
        ):
            with self.subTest(record=record):
                self.assertFalse(any("UPDATE" in x for x in check(record,expected=403)))
        check({**valid,"local_opt_in_attested_at":now},expected=409)
        check(valid,grant_value={**grant,"edition":"STANDARD"},expected=403)
        check(valid,grant_value={**grant,"status":"ASSIGNED"},expected=403)

    def test_local_standing_status_is_read_only_and_never_declares_ready(self):
        req=workshop.WorkshopAuth(
            requestId=str(uuid.uuid4()),nonce=str(uuid.uuid4()),
            sentAt=datetime.now(timezone.utc),installationId=self.iid,
            deviceId="d"*32,discoveryCredential="c"*64)
        grant={"status":"WAITING","edition":"PRO","enabled":True,
               "mesh_node_id":self.node}
        record={"approved_mesh_node_id":self.node,
                "device_scope":"CLIENT_DIAGNOSTIC",
                "owner_approved_at":datetime.now(timezone.utc),
                "revoked_at":None,"local_opt_in_attested_at":None,
                "prior_consent_sha256":"a"*64}
        db=MagicMock()
        with patch.object(workshop,"_schema"),patch.object(workshop,"_authenticate"), \
             patch.object(workshop,"_grant",return_value=grant), \
             patch.object(workshop,"standing_authorization_record",return_value=record), \
             patch.object(workshop,"engine") as engine:
            engine.connect.return_value.__enter__.return_value=db
            result=workshop.workshop_standing_status(req)
        self.assertEqual(result["deviceScope"],"CLIENT_DIAGNOSTIC")
        self.assertTrue(result["ownerPrepared"])
        self.assertFalse(result["localOptInAttested"])
        self.assertFalse(result["unattendedReady"])
        self.assertEqual(db.execute.call_count,0)

    def test_owner_documented_prior_consent_requires_device_binding_and_local_opt_in(self):
        grant={"status":"WAITING","edition":"PRO","enabled":True,
               "mesh_node_id":self.node}
        for scope,hash_value in (
            ("PAID_PRO","a"*64),
            ("CLIENT_DIAGNOSTIC","unverified"),
        ):
            with self.subTest(scope=scope),self.assertRaises(HTTPException):
                workshop.prepare_standing_authorization_for_owner(self.iid,scope,hash_value)
        statements=[]
        db=MagicMock()
        def execute(statement,params=None):
            sql=str(statement)
            statements.append((sql,params))
            result=MagicMock()
            if "FROM guard.workshop_standing_remote_authorizations" in sql:
                result.mappings.return_value.first.return_value=None
            return result
        db.execute.side_effect=execute
        with patch.object(workshop,"_schema"),patch.object(workshop,"engine") as engine, \
             patch.object(workshop,"_grant",return_value=grant), \
             patch.object(mesh,"verify_registered_node",return_value=True) as verify:
            engine.connect.return_value.__enter__.return_value=db
            engine.begin.return_value.__enter__.return_value=db
            reply=workshop.prepare_standing_authorization_for_owner(
                self.iid,"CLIENT_DIAGNOSTIC","b"*64)
            verify.assert_called_once_with(self.node)
        self.assertEqual(reply,{"recorded":True,"localDeviceConsentPending":True,
                               "meshGroupVerificationPending":True,"unattendedReady":False})
        insertion=next((query,params) for query,params in statements
                       if "INSERT INTO guard.workshop_standing_remote_authorizations" in query)
        self.assertIn("local_opt_in_attested_at=NULL",insertion[0])
        self.assertEqual(insertion[1]["node"],self.node)
        self.assertEqual(insertion[1]["receipt"],"b"*64)
        self.assertTrue(any("OWNER_APPROVED" in query for query,_ in statements))
        self.assertFalse(any("share" in query.lower() and "insert" in query.lower()
                             for query,_ in statements))

    def test_owner_cannot_reapprove_without_revoking_existing_authorization(self):
        db=MagicMock()
        def execute(statement,params=None):
            result=MagicMock()
            if "FROM guard.workshop_standing_remote_authorizations" in str(statement):
                result.mappings.return_value.first.return_value={"revoked_at":None}
            return result
        db.execute.side_effect=execute
        grant={"status":"WAITING","edition":"PRO","enabled":True,
               "mesh_node_id":self.node}
        with patch.object(workshop,"_schema"),patch.object(workshop,"engine") as engine, \
             patch.object(workshop,"_grant",return_value=grant), \
             patch.object(mesh,"verify_registered_node",return_value=True):
            engine.connect.return_value.__enter__.return_value=db
            engine.begin.return_value.__enter__.return_value=db
            with self.assertRaises(HTTPException) as caught:
                workshop.prepare_standing_authorization_for_owner(
                    self.iid,"CLIENT_DIAGNOSTIC","a"*64)
        self.assertEqual(caught.exception.status_code,409)
        self.assertFalse(any("INSERT INTO guard.workshop_standing_remote_authorizations" in str(c.args[0])
                             for c in db.execute.call_args_list))

    def test_owner_revocation_is_audited_and_persists_on_mesh_revoke_failure(self):
        def run(mesh_fails):
            db=MagicMock()
            statements=[]
            def execute(statement, params=None):
                sql=str(statement)
                statements.append(sql)
                result=MagicMock()
                if "FROM guard.workshop_standing_remote_authorizations" in sql:
                    result.mappings.return_value.first.return_value={"revoked_at":None}
                return result
            db.execute.side_effect=execute
            with patch.object(workshop,"_schema"), \
                 patch.object(workshop,"engine") as engine, \
                 patch.object(workshop,"_open",
                              side_effect=HTTPException(502,"Mesh revoke failed")
                              if mesh_fails else None) as close:
                engine.begin.return_value.__enter__.return_value=db
                if mesh_fails:
                    with self.assertRaises(HTTPException) as caught:
                        workshop.revoke_standing_authorization_for_owner(self.iid)
                    self.assertEqual(caught.exception.status_code,502)
                    self.assertIn("cofnięte",caught.exception.detail)
                else:
                    reply=workshop.revoke_standing_authorization_for_owner(self.iid)
                    self.assertEqual(reply,{"revoked":True,
                        "previouslyActive":True,"shareRevokeConfirmed":True})
                close.assert_called_once_with(db,self.iid,entitlement_lost=True)
            self.assertTrue(any("UPDATE guard.workshop_standing_remote_authorizations" in q
                                and "revoked_at=:now" in q for q in statements))
            self.assertTrue(any("INSERT INTO guard.workshop_standing_remote_audit" in q
                                for q in statements))
        run(mesh_fails=False)
        run(mesh_fails=True)

    def test_standing_revocation_is_idempotent_and_downgrade_invalidates(self):
        db=MagicMock()
        seen=[]
        def execute(statement,params=None):
            sql=str(statement)
            seen.append(sql)
            result=MagicMock()
            if "FROM guard.workshop_standing_remote_authorizations" in sql:
                result.mappings.return_value.first.return_value={"revoked_at":datetime.now(timezone.utc)}
            return result
        db.execute.side_effect=execute
        with patch.object(workshop,"_schema"),patch.object(workshop,"engine") as engine, \
             patch.object(workshop,"_open") as close:
            engine.begin.return_value.__enter__.return_value=db
            reply=workshop.revoke_standing_authorization_for_owner(self.iid)
            self.assertEqual(reply,{"revoked":True,
                "previouslyActive":False,"shareRevokeConfirmed":True})
            close.assert_not_called()
        self.assertFalse(any("INSERT INTO guard.workshop_standing_remote_audit" in q
                             for q in seen))
        with patch.object(workshop,"_open") as close, \
             patch.object(workshop,"invalidate_standing_authorization") as invalidate:
            workshop.close_before_rights_change(db,self.iid)
            close.assert_called_once_with(db,self.iid,entitlement_lost=True)
            invalidate.assert_called_once_with(db,self.iid,"SERVICE_RIGHTS_CHANGED")
        with self.assertRaises(ValueError):
            workshop.invalidate_standing_authorization(db,self.iid,"ALLOW_ALL")

    def test_standing_permission_needs_separate_prior_consent_and_exact_node(self):
        now=datetime.now(timezone.utc)
        grant={
            "status":"WAITING", "edition":"PRO", "enabled":True,
            "mesh_node_id":self.node,
        }
        receipt={
            "approved_mesh_node_id":self.node,
            "device_scope":"CLIENT_DIAGNOSTIC",
            "owner_approved_at":now,
            "local_opt_in_attested_at":now,
            "prior_consent_sha256":"a"*64,
            "revoked_at":None,
        }
        valid=workshop.standing_authorization_record_valid
        self.assertFalse(valid(grant,None))
        self.assertTrue(valid(grant,receipt))
        for changed in (
            {"approved_mesh_node_id":"node//"+"Z"*64},
            {"device_scope":"PAID_PRO"},
            {"owner_approved_at":None},
            {"local_opt_in_attested_at":None},
            {"prior_consent_sha256":"not-a-digest"},
            {"revoked_at":now},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(valid(grant,{**receipt,**changed}))
        for changed in (
            {"status":"ASSIGNED"},
            {"enabled":False},
            {"edition":"STANDARD"},
            {"mesh_node_id":None},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(valid({**grant,**changed},receipt))

    def test_standing_service_node_requires_exact_online_dedicated_group(self):
        diagnostic_group="mesh//"+"D"*64
        node="node//"+"A"*64
        row={"_id":node,"meshid":diagnostic_group,"name":"PersistentSCM","conn":1}
        with patch.dict(os.environ,{
            "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID":diagnostic_group,
            "MESH_CENTRAL_OWNER_OWNED_MESH_ID":"mesh//"+"E"*64,
        }), patch.object(mesh,"_base_command",return_value=["meshctrl","DeviceSharing"]), \
             patch.object(mesh,"_run",return_value=json.dumps([row])):
            self.assertEqual(
                mesh.verify_standing_service_node(node,"CLIENT_DIAGNOSTIC"),node)
            for wrong in (
                [{**row,"meshid":"mesh//"+"Z"*64}],
                [{**row,"conn":0}],
                [{**row,"conn":True}],
                [row,row],
                [{**row,"_id":"node//"+"B"*64}],
            ):
                with self.subTest(wrong=wrong), patch.object(
                    mesh,"_run",return_value=json.dumps(wrong)
                ), self.assertRaises(mesh.MeshCentralError):
                    mesh.verify_standing_service_node(node,"CLIENT_DIAGNOSTIC")
            with self.assertRaises(mesh.MeshCentralError):
                mesh.verify_standing_service_node(node,"OWNED_WORKSHOP")
            with self.assertRaises(mesh.MeshCentralError):
                mesh.verify_standing_service_node(node,"PAID_PRO")
        with patch.dict(os.environ,{"MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID":""}), \
             patch.object(mesh,"_run") as run, self.assertRaises(mesh.MeshCentralError):
            mesh.verify_standing_service_node(node,"CLIENT_DIAGNOSTIC")
        run.assert_not_called()

    def test_standing_scm_node_text_online_fallback_requires_exact_identity(self):
        group="mesh//"+"D"*64
        node="node//"+"A"*64
        row={"_id":node,"meshid":group,"name":"SCM Service"}
        text_online="A"*64+', "SCM Service", 2, 1, 0\n'
        with patch.dict(os.environ,{"MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID":group}), \
             patch.object(mesh,"_base_command",return_value=["meshctrl","DeviceSharing"]), \
             patch.object(mesh,"_run",side_effect=[json.dumps([row]),text_online]):
            self.assertEqual(mesh.verify_standing_service_node(node,"CLIENT_DIAGNOSTIC"),node)
        for bad in (text_online+text_online, text_online.replace(", 1, 0",", 0, 0"),
                    text_online.replace("SCM Service","foreign agent")):
            with patch.dict(os.environ,{"MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID":group}), \
                 patch.object(mesh,"_base_command",return_value=["meshctrl","DeviceSharing"]), \
                 patch.object(mesh,"_run",side_effect=[json.dumps([row]),bad]), \
                 self.assertRaises(mesh.MeshCentralError):
                mesh.verify_standing_service_node(node,"CLIENT_DIAGNOSTIC")

    def test_authoritative_backend_entitlement_modes_are_separate(self):
        base={"status":"WAITING","edition":"PRO","enabled":True}
        cases=[
            (base,"SERVICE_PRO"),
            ({**base,"edition":"STANDARD"},"SERVICE_STANDARD"),
            ({**base,"enabled":False},"SERVICE_DISABLED"),
            ({**base,"status":"ASSIGNED"},"CUSTOMER_LICENSE"),
            ({**base,"status":"PROVISIONED"},"CUSTOMER_LICENSE"),
            ({**base,"status":"UNINSTALLED"},"INACTIVE_INSTALLATION"),
            ({**base,"status":"ARCHIVED"},"INACTIVE_INSTALLATION"),
            (None,"UNREGISTERED"),
        ]
        for grant,mode in cases:
            with self.subTest(mode=mode,grant=grant):
                self.assertEqual(workshop.remote_entitlement_mode(grant),mode)
                self.assertEqual(workshop._eligible(grant),mode=="SERVICE_PRO")

    def test_paid_pro_is_never_treated_as_service_pro_by_remote_poll(self):
        body = workshop.WorkshopAuth(
            requestId="test-request-id", nonce="test-nonce-id",
            sentAt=datetime.now(timezone.utc), installationId=self.iid,
            deviceId="test-device-123456789", discoveryCredential="x"*32,
        )
        for status in ("ASSIGNED", "PROVISIONED"):
            with self.subTest(status=status), patch.object(
                workshop.license, "_authenticate_pending", create=True,
                return_value={"status":status},
            ):
                with self.assertRaises(HTTPException) as caught:
                    workshop._authenticate(body)
                self.assertEqual(caught.exception.status_code, 409)
                self.assertIn("licencję klienta", caught.exception.detail)
        for status in ("ARCHIVED", "UNINSTALLED", "IGNORED"):
            with self.subTest(status=status), patch.object(
                workshop.license, "_authenticate_pending", create=True,
                return_value={"status":status},
            ):
                with self.assertRaises(HTTPException) as caught:
                    workshop._authenticate(body)
                self.assertEqual(caught.exception.status_code, 403)
        with patch.object(
            workshop.license, "_authenticate_pending", create=True,
            return_value={"status":"WAITING"},
        ):
            self.assertEqual(workshop._authenticate(body)["status"], "WAITING")

    def test_unattended_blocked_without_independent_owner_attestation(self):
        with self.assertRaises(mesh.MeshCentralError):
            mesh.create_workshop_share(self.node, "Workshop", ["desktop"])
        with self.assertRaises(HTTPException) as caught:
            workshop.request_for_owner(self.iid)
        self.assertEqual(caught.exception.status_code, 503)

    def test_future_service_share_is_not_silent_and_never_exposes_files(self):
        with patch.object(mesh, "_base_command", return_value=["meshctrl","DeviceSharing"]), \
             patch.object(mesh, "_run", return_value="ID: test-share\nURL: https://mesh.multi-servis.pl/guest\n") as run:
            mesh._create_share(self.node, "Standing service diagnostics",
                               ["desktop"], workshop_unattended=True)
        cmd=run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--consent")+1], "notify,bar")
        self.assertEqual(cmd[cmd.index("--type")+1], "desktop")

    def test_commercial_share_remains_prompt_and_bar(self):
        with patch.object(mesh, "_base_command", return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(mesh, "_run", return_value="ID: share\nURL: https://mesh.multi-servis.pl/guest\n") as run:
            mesh.create_share(self.node, "Commercial", ["desktop"])
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--consent") + 1], "prompt,bar")

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

    def test_commercial_mode_reuses_own_workshop_node_but_never_a_foreign_one(self):
        # The single installer/service keeps the same node across PRO modes.
        # Any other installation's binding remains an explicit HTTP 409.
        body=paid.AgentSessionMeshBody(**self.auth(),installationCredential="x"*32)
        own_id=self.iid
        install={"id":own_id,"service_device_id":None,"mesh_node_id":self.node}
        self.row["installation_id"]=own_id
        def run(foreign_owner=None, active_workshop_share=False):
            db=MagicMock()
            def execute(query, params=None):
                statement=str(query)
                result=MagicMock()
                if "SELECT * FROM guard.installations" in statement:
                    result.mappings.return_value.first.return_value=install
                elif "SELECT * FROM guard.remote_sessions WHERE id=:sid" in statement:
                    result.mappings.return_value.first.return_value=self.row
                elif "SELECT 1 FROM guard.workshop_mesh_nodes" in statement:
                    self.assertEqual(params["iid"], own_id)
                    result.first.return_value=((1,) if foreign_owner and foreign_owner != own_id else None)
                elif "SELECT 1 FROM guard.workshop_remote_sessions" in statement:
                    result.first.return_value=((1,) if active_workshop_share else None)
                return result
            db.execute.side_effect=execute
            with patch.object(workshop,"_schema"), patch.object(paid,"engine") as engine, \
                 patch.object(paid,"_require_agent",return_value=install), \
                 patch.object(paid,"_has_active_remote_pro",return_value=True), \
                 patch.object(paid,"_plan_change_pending",return_value=False), \
                 patch.object(mesh,"verify_session_node",return_value=self.node), \
                 patch.object(paid,"_audit"):
                engine.connect.return_value.__enter__.return_value=db
                engine.begin.return_value.__enter__.return_value=db
                return paid.agent_session_mesh_enroll(body)
        self.assertTrue(run(foreign_owner=own_id)["accepted"])
        with self.assertRaises(HTTPException) as caught:
            run(foreign_owner=uuid.uuid4())
        self.assertEqual(caught.exception.status_code,409)
        with self.assertRaises(HTTPException) as caught:
            run(foreign_owner=own_id, active_workshop_share=True)
        self.assertEqual(caught.exception.status_code,409)

    def test_workshop_cross_mode_binds_same_install_only_and_preserves_session(self):
        # Validate both session enrollment and pre-enrollment SQL guards.
        import inspect
        session_src=inspect.getsource(workshop.workshop_session_mesh_enroll)
        general_src=inspect.getsource(workshop.workshop_mesh_enroll)
        paid_src=inspect.getsource(paid.agent_session_mesh_enroll)
        self.assertIn("WHERE mesh_node_id=:node AND id<>:iid",session_src)
        self.assertIn("WHERE mesh_node_id=:node AND id<>:iid",general_src)
        self.assertIn("WHERE mesh_node_id=:node AND installation_id<>:iid",paid_src)
        self.assertIn("SELECT pg_advisory_xact_lock(hashtext(:node))",general_src)
        self.assertIn("THEN owned.session_id ELSE NULL END",general_src)
        # A still-active opposite-mode share must be revoked/ended first.
        self.assertIn("SELECT 1 FROM guard.remote_sessions",session_src)
        self.assertIn("SELECT 1 FROM guard.remote_sessions",general_src)
        self.assertIn("SELECT 1 FROM guard.workshop_remote_sessions",paid_src)

    def test_workshop_pre_enroll_allows_own_commercial_node_not_foreign(self):
        body=workshop.WorkshopMeshEnrollment(**{
            key: val for key,val in self.auth().items() if key != "sessionId"
        }, discoveryCredential="x"*32)
        def run(foreign_owner=None, active_commercial=False):
            db=MagicMock()
            def execute(statement, params=None):
                sql=str(statement)
                result=MagicMock()
                if "SELECT enabled,edition FROM guard.workshop_grants" in sql:
                    result.mappings.return_value.first.return_value={"enabled":True,"edition":"PRO"}
                elif "SELECT 1 FROM guard.installations" in sql:
                    self.assertEqual(params["iid"],self.iid)
                    result.first.return_value=((1,) if foreign_owner and foreign_owner != self.iid else None)
                elif "SELECT 1 FROM guard.remote_sessions" in sql:
                    result.first.return_value=((1,) if active_commercial else None)
                elif "SELECT mesh_node_id FROM guard.workshop_mesh_nodes" in sql:
                    result.scalar_one_or_none.return_value=self.node
                return result
            db.execute.side_effect=execute
            grant={"mesh_node_id":self.node,"edition":"PRO","enabled":True,"status":"NEW"}
            with patch.object(workshop,"_schema"), patch.object(workshop,"_authenticate"), \
                 patch.object(workshop,"_grant",return_value=grant), \
                 patch.object(workshop,"_eligible",return_value=True), \
                 patch.object(workshop,"engine") as engine, \
                 patch.object(mesh,"verify_registered_node",return_value=True):
                engine.connect.return_value.__enter__.return_value=db
                engine.begin.return_value.__enter__.return_value=db
                result=workshop.workshop_mesh_enroll(body)
            return result
        self.assertTrue(run(foreign_owner=self.iid)["accepted"])
        with self.assertRaises(HTTPException) as caught:
            run(foreign_owner=uuid.uuid4())
        self.assertEqual(caught.exception.status_code,409)
        with self.assertRaises(HTTPException) as caught:
            run(foreign_owner=self.iid,active_commercial=True)
        self.assertEqual(caught.exception.status_code,409)

    def test_workshop_consent_refreshes_enrollment_deadline(self):
        # Consent near the end of the original request must still allow agent enrollment.
        body = workshop.WorkshopDecision(**self.auth(), discoveryCredential="x"*32,
                                         allowDesktop=True)
        old_expiry = datetime.now(timezone.utc) + timedelta(seconds=2)
        pending = {**self.row, "status":"REQUESTED", "expires_at":old_expiry,
                   "requested_by_name":"OWNER", "subject":"Test",
                   "requested_capabilities":["desktop"], "requested_at":datetime.now(timezone.utc),
                   "connected_at":None, "reconnect_until":None,
                   "mesh_share_expires_at":None, "last_error":None}
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

    def test_concurrent_owner_connect_does_not_overwrite_newer_share(self):
        from types import SimpleNamespace
        row = {**self.row, "requested_by_name":"OWNER"}
        changed = {**row, "status":"CONNECT_READY", "mesh_public_id":"share-winner"}
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.side_effect = [row, changed]
        grant = {"mesh_node_id":self.node, "mesh_session_id":self.sid}
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value=grant), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(mesh, "create_share",
                          return_value=SimpleNamespace(public_id="share-loser",url="https://example.test")) as create, \
             patch.object(mesh, "revoke_share") as revoke:
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException):
                workshop.connect_for_owner(self.sid)
        create.assert_called_once()
        revoke.assert_called_once_with(self.node, "share-loser")
        self.assertFalse(any("UPDATE guard.workshop_remote_sessions" in str(c.args[0])
                             for c in db.execute.call_args_list))

    def test_share_expiring_during_create_is_rejected_and_new_share_revoked(self):
        from types import SimpleNamespace
        live = {**self.row, "status":"CONNECT_READY", "mesh_public_id":"old-share",
                "mesh_share_expires_at":datetime.now(timezone.utc)+timedelta(minutes=10)}
        expired = {**live, "mesh_share_expires_at":
                   datetime.now(timezone.utc)-timedelta(seconds=1)}
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.side_effect = [live, expired]
        grant = {"mesh_node_id":self.node, "mesh_session_id":self.sid}
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value=grant), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(mesh, "create_share",
                          return_value=SimpleNamespace(public_id="new-share",url="https://example.test")), \
             patch.object(mesh, "revoke_share") as revoke:
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException):
                workshop.connect_for_owner(self.sid)
        self.assertEqual(revoke.call_count, 2)
        revoke.assert_any_call(self.node, "old-share")
        revoke.assert_any_call(self.node, "new-share")
        self.assertFalse(any("UPDATE guard.workshop_remote_sessions" in str(c.args[0])
                             for c in db.execute.call_args_list))

    def test_mesh_creation_failure_preserves_session_state(self):
        import inspect
        source = inspect.getsource(paid.remote_session_connect)
        self.assertIn("SET last_error=:error,last_activity_at=:now", source)
        self.assertIn("AND status IN ('CONSENTED','CONNECT_READY','ACTIVE')", source)
        self.assertIn("AND mesh_public_id IS NOT DISTINCT FROM :expected_public_id", source)
        self.assertIn("if updated.rowcount:", source)
        self.assertNotIn("SET status='ERROR',last_error=:error", source)

    def test_paid_consent_rejects_exact_expiry_boundary(self):
        import inspect
        source = inspect.getsource(paid.agent_remote_decision)
        self.assertIn('if row["expires_at"] <= now:', source)

    def test_expired_mesh_creation_cannot_publish_workshop_share(self):
        import inspect
        source = inspect.getsource(workshop.connect_for_owner)
        self.assertIn("if share_expires <= _now():", source)
        self.assertIn("Nowy link MeshCentral wygasł przed zapisem.", source)
        self.assertIn("meshcentral.revoke_share(node,share.public_id)", source)

    def test_expired_mesh_creation_cannot_publish_paid_share(self):
        import inspect
        source = inspect.getsource(paid.remote_session_connect)
        self.assertIn("if share_expires <= datetime.now(timezone.utc):", source)
        self.assertIn("Nowy link MeshCentral wygasł przed zapisem.", source)
        self.assertIn("meshcentral.revoke_share(node_id, share.public_id)", source)

    def test_paid_share_expiry_is_shared_between_database_and_response(self):
        import inspect
        source = inspect.getsource(paid.remote_session_connect)
        self.assertIn('share_expires = datetime.now(timezone.utc) + timedelta(minutes=60)', source)
        self.assertIn('"expires_at": share_expires', source)
        self.assertIn('"expiresAt": share_expires.isoformat()', source)

    def test_paid_connect_checks_share_identity_and_consent_after_mesh_call(self):
        # Regression contract: concurrent OWNER actions must never overwrite
        # a newer public share or consent and must check actual lease validity.
        import inspect
        source = inspect.getsource(paid.remote_session_connect)
        self.assertIn('current["mesh_public_id"] != existing_public_id', source)
        self.assertIn('list(current["granted_capabilities"] or []) != granted', source)
        self.assertIn('current["ended_at"] is not None', source)
        self.assertIn('current["mesh_share_expires_at"] <= datetime.now(timezone.utc)', source)
        self.assertIn('current["expires_at"] <= datetime.now(timezone.utc)', source)

    def test_paid_expiry_query_includes_missing_share_lease(self):
        db = MagicMock()
        db.execute.return_value.mappings.return_value.all.return_value = []
        db.execute.return_value.mappings.return_value.first.return_value = None
        paid._expire_and_find_open(db, self.iid)
        query = str(db.execute.call_args_list[0].args[0])
        self.assertIn("rs.mesh_share_expires_at IS NULL", query)
        self.assertIn("rs.mesh_share_expires_at<=:now", query)
        self.assertIn("rs.expires_at<=:now", query)

    def test_missing_share_lease_is_expired_and_revoked(self):
        active = {**self.row, "status":"CONNECT_READY", "mesh_public_id":"orphan-share",
                  "mesh_share_expires_at":None}
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value = active
        grant = {"edition":"PRO", "enabled":True, "status":"NEW",
                 "mesh_node_id":self.node, "mesh_session_id":self.sid}
        with patch.object(workshop, "_grant", return_value=grant), \
             patch.object(mesh, "revoke_share") as revoke, \
             patch.object(workshop, "_event") as event:
            self.assertIsNone(workshop._open(db, self.iid))
        revoke.assert_called_once_with(self.node, "orphan-share")
        self.assertTrue(any("SET status='EXPIRED'" in str(c.args[0])
                            for c in db.execute.call_args_list))
        event.assert_called_once()

    def test_owner_reconnect_rejects_expired_share_without_mesh_call(self):
        expired = {**self.row, "status":"CONNECT_READY",
                   "mesh_public_id":"old-share",
                   "mesh_share_expires_at":datetime.now(timezone.utc)-timedelta(seconds=1)}
        db = MagicMock()
        db.execute.return_value.mappings.return_value.first.return_value = expired
        grant = {"mesh_node_id":self.node, "mesh_session_id":self.sid}
        with patch.object(workshop, "_schema"), \
             patch.object(workshop, "engine") as engine, \
             patch.object(workshop, "_grant", return_value=grant), \
             patch.object(workshop, "_eligible", return_value=True), \
             patch.object(mesh, "create_share") as create, \
             patch.object(mesh, "revoke_share") as revoke:
            engine.begin.return_value.__enter__.return_value = db
            with self.assertRaises(HTTPException) as caught:
                workshop.connect_for_owner(self.sid)
        self.assertEqual(caught.exception.status_code, 410)
        create.assert_not_called()
        revoke.assert_not_called()

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
