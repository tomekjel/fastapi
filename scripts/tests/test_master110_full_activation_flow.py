"""MASTER110: actual FastAPI provision functions + actual PostgreSQL transactions.

KeyGate is a deterministic in-process stub. Test DB is the ephemeral
postgres:16 service in GitHub Actions. No production access or real credentials.
"""
from __future__ import annotations
import ast
import hashlib
import os
from pathlib import Path
import re
import secrets
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text

DB=os.environ.get("MASTER110_TEST_POSTGRES","")
assert DB and ("127.0.0.1" in DB or "localhost" in DB), "Only local test PostgreSQL allowed"
DB=DB.replace("postgresql://","postgresql+psycopg://",1)
engine=create_engine(DB,pool_pre_ping=True)
SOURCE=Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
TREE=ast.parse(SOURCE)
FUNCTIONS={
    n.name:n for n in TREE.body
    if isinstance(n,ast.FunctionDef)
    and n.name in {"provision","_begin_keygate_provision_attempt",
                   "_finish_keygate_provision_attempt","_update_installation_mirror"}
}
assert len(FUNCTIONS)==4
for item in FUNCTIONS.values():item.decorator_list=[]
future=ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0)
CODE=compile(ast.fix_missing_locations(ast.Module(body=[future,*FUNCTIONS.values()],type_ignores=[])),"<actual-activation-handler>","exec")

class HTTPException(Exception):
    def __init__(self,status_code,detail):self.status_code=status_code;super().__init__(detail)

class FakeKeyGate:
    def __init__(self):self.activations=[];self.deactivations=[];self.mode="ok"
    def activate(self,license_key,device_id,installation_id):
        self.activations.append((license_key,device_id,installation_id))
        if self.mode=="timeout":raise HTTPException(502,"Unknown KeyGate outcome")
        if self.mode=="rejected":raise HTTPException(409,"KeyGate refused")
        if self.mode=="wrong-id":return {"license_id":"DIFFERENT-LICENSE"}
        return {"license_id":"KG-TEST-ID"}
    def deactivate(self,license_key,device_id):
        self.deactivations.append((license_key,device_id))

class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use actual backend CREATE TABLE definitions for these three records,
        # with foreign-key targets provisioned in isolated temp database.
        raw=SOURCE.split('_SCHEMA_SQL = """',1)[1].split('"""',1)[0]
        with engine.begin() as con:
            con.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
            con.execute(text("CREATE SCHEMA IF NOT EXISTS core"))
            con.execute(text("CREATE SCHEMA IF NOT EXISTS service"))
            con.execute(text("CREATE SCHEMA IF NOT EXISTS guard"))
            con.execute(text("CREATE TABLE IF NOT EXISTS core.devices(id uuid PRIMARY KEY)"))
            con.execute(text("CREATE TABLE IF NOT EXISTS service.service_orders(id uuid PRIMARY KEY,device_id uuid)"))
            # Extract the actual backend table DDL (not an imitation schema).
            for name in ["license_links","pending_installations","installations","keygate_provision_attempts"]:
                match=re.search(r"CREATE TABLE IF NOT EXISTS guard\."+name+r" \((.*?)\);",raw,re.S)
                assert match,name
                con.execute(text("CREATE TABLE IF NOT EXISTS guard."+name+" ("+match.group(1)+")"))
            ix=re.search(r"CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_keygate_provision_unresolved(.*?);",raw,re.S)
            assert ix
            con.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_keygate_provision_unresolved"+ix.group(1)))
    def setUp(self):
        with engine.begin() as con:
            con.execute(text("TRUNCATE guard.keygate_provision_attempts,guard.installations,guard.pending_installations,guard.license_links,service.service_orders,core.devices CASCADE"))
        self.iid=uuid.uuid4();self.rid=uuid.uuid4();self.device_uuid=uuid.uuid4()
        self.device_id="DEVICE-TEST";self.secret="discovery-secret"
        self.license_key="KG-"+"A"*8+"-"+"B"*8+"-"+"C"*8+"-"+"D"*8
        self.valid_until=datetime.now(timezone.utc)+timedelta(days=120)
        self.keygate=FakeKeyGate()
        with engine.begin() as con:
            con.execute(text("INSERT INTO core.devices(id) VALUES(:id)"),{"id":self.device_uuid})
            con.execute(text("INSERT INTO service.service_orders(id,device_id) VALUES(:id,:dev)"),{"id":self.rid,"dev":self.device_uuid})
            con.execute(text("""
                INSERT INTO guard.license_links
                (reception_id,reception_number,service_device_id,keygate_license_id,
                 keygate_plan_id,license_key_hash,plan_code,duration_months,
                 lifecycle,rebind_pending,valid_until)
                VALUES(:rid,'REC-TEST',:dev,'KG-TEST-ID','plan-test',:hash,
                       'multi_guard_pro',12,'ACTIVE',TRUE,:valid_until)
            """),{"rid":self.rid,"dev":self.device_uuid,"hash":hashlib.sha256(self.license_key.encode()).hexdigest(),"valid_until":self.valid_until})
            con.execute(text("""
                INSERT INTO guard.pending_installations
                (installation_id,device_id,discovery_credential_sha256,status,
                 assigned_reception_id,assigned_license_id)
                VALUES(:iid,:did,:secret,'ASSIGNED',:rid,'KG-TEST-ID')
            """),{"iid":self.iid,"did":self.device_id,"secret":hashlib.sha256(self.secret.encode()).hexdigest(),"rid":self.rid})
        env={
            "uuid":uuid,"engine":engine,"text":text,"secrets":secrets,"HTTPException":HTTPException,
            "_KEY_PATTERN":re.compile(r"^KG-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}$"),
            "_hash":lambda value:hashlib.sha256(value.encode()).hexdigest(),
            "_utcnow":lambda:datetime.now(timezone.utc),
            "_ensure_schema":lambda:None,
            "_normalize_link":lambda link:dict(link),
            "_signed_envelope":lambda link:{"testLicenseId":link["keygate_license_id"]},
            "_keygate_activate":self.keygate.activate,
            "_keygate_deactivate":self.keygate.deactivate,
        }
        env["_link_by_key"]=lambda key: self.fetch_link()
        env["_pending_installation"]=lambda iid: self.fetch_pending(iid)
        exec(CODE,env)
        self.provision=env["provision"]
        self.req=types.SimpleNamespace(provisioning_token=self.license_key,
            installation_id=str(self.iid),device_id=self.device_id,
            discovery_credential=self.secret,request_id="request-test",app_version="test")
    def fetch_link(self):
        with engine.connect() as con:
            x=con.execute(text("SELECT * FROM guard.license_links WHERE reception_id=:rid"),{"rid":self.rid}).mappings().first()
        return dict(x) if x else None
    def fetch_pending(self,iid):
        with engine.connect() as con:
            x=con.execute(text("SELECT * FROM guard.pending_installations WHERE installation_id=:iid"),{"iid":iid}).mappings().first()
        return dict(x) if x else None
    def attempts(self):
        with engine.connect() as con:
            return [dict(x) for x in con.execute(text("SELECT * FROM guard.keygate_provision_attempts ORDER BY created_at")).mappings()]
    def test_success_preserves_validity_and_provisions_once(self):
        response=self.provision(self.req)
        self.assertEqual(response["signedLicense"]["testLicenseId"],"KG-TEST-ID")
        link=self.fetch_link()
        self.assertEqual(link["installation_id"],self.iid)
        self.assertEqual(link["device_id"],self.device_id)
        self.assertEqual(link["valid_until"],self.valid_until)
        self.assertEqual(link["lifecycle"],"ACTIVE")
        self.assertFalse(link["rebind_pending"])
        self.assertEqual(self.fetch_pending(self.iid)["status"],"PROVISIONED")
        self.assertEqual(self.attempts()[0]["state"],"COMMITTED")
        self.assertEqual(len(self.keygate.activations),1)
        with engine.connect() as con:
            mirror=con.execute(text("SELECT * FROM guard.installations WHERE installation_external_id=:iid"),{"iid":self.iid}).mappings().one()
        self.assertTrue(mirror["is_current"])
        self.assertEqual(mirror["license_id"],"KG-TEST-ID")
    def test_keygate_reject_blocks_and_keeps_existing_term(self):
        self.keygate.mode="rejected"
        with self.assertRaises(HTTPException):self.provision(self.req)
        self.assertIsNone(self.fetch_link()["installation_id"])
        self.assertEqual(self.fetch_link()["valid_until"],self.valid_until)
        self.assertEqual(self.attempts()[0]["state"],"NEEDS_REVIEW")
        self.assertEqual(self.keygate.deactivations,[])
    def test_uncertain_keygate_response_blocks_retry(self):
        self.keygate.mode="timeout"
        with self.assertRaises(HTTPException):self.provision(self.req)
        self.assertEqual(self.attempts()[0]["state"],"NEEDS_REVIEW")
        self.keygate.mode="ok"
        with self.assertRaises(HTTPException) as error:self.provision(self.req)
        self.assertEqual(error.exception.status_code,409)
        self.assertEqual(len(self.keygate.activations),1)
    def test_sql_failure_after_keygate_compensates_and_retains_term(self):
        # Force the pending-installation SQL UPDATE to fail after KeyGate
        # activation. PostgreSQL rollback must restore the license row.
        with engine.begin() as con:
            con.execute(text("""
                CREATE OR REPLACE FUNCTION guard.master110_test_fail_pending()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                  IF NEW.status='PROVISIONED' THEN
                    RAISE EXCEPTION 'simulated pending commit failure';
                  END IF;
                  RETURN NEW;
                END; $$
            """))
            con.execute(text("""
                CREATE TRIGGER master110_test_fail_pending_trigger
                BEFORE UPDATE ON guard.pending_installations
                FOR EACH ROW EXECUTE FUNCTION guard.master110_test_fail_pending()
            """))
        try:
            with self.assertRaises(Exception):
                self.provision(self.req)
        finally:
            with engine.begin() as con:
                con.execute(text("DROP TRIGGER IF EXISTS master110_test_fail_pending_trigger ON guard.pending_installations"))
                con.execute(text("DROP FUNCTION IF EXISTS guard.master110_test_fail_pending()"))
        self.assertEqual(len(self.keygate.activations),1)
        self.assertEqual(len(self.keygate.deactivations),1)
        self.assertIsNone(self.fetch_link()["installation_id"])
        self.assertEqual(self.fetch_link()["valid_until"],self.valid_until)
        self.assertEqual(self.attempts()[0]["state"],"NEEDS_REVIEW")
    def test_owner_revoked_license_is_not_activated(self):
        with engine.begin() as con:
            con.execute(text("UPDATE guard.license_links SET lifecycle='REVOKED'"))
        with self.assertRaises(HTTPException) as error:self.provision(self.req)
        self.assertEqual(error.exception.status_code,409)
        self.assertEqual(len(self.keygate.activations),0)

if __name__=="__main__":unittest.main()
