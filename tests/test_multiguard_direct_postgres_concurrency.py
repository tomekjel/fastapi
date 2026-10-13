"""Real PostgreSQL transactions for DIRECT; KeyGate is a controlled test double.

Runs only against localhost/multiservis_ci. Each test owns a random schema;
no application tables, real licences or customer records are accessed.
"""
import ast
import logging
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


class HTTPError(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        super().__init__(detail)


class DirectPostgresTests(unittest.TestCase):
    def setUp(self):
        url = os.environ["OWNER_TEST_DATABASE_URL"]
        parsed_url = make_url(url)
        if (parsed_url.host not in {"127.0.0.1", "localhost"}
                or parsed_url.database != "multiservis_ci"
                or parsed_url.get_backend_name() != "postgresql"):
            raise RuntimeError("Only isolated localhost PostgreSQL multiservis_ci is allowed")
        self.engine = create_engine(url, pool_size=5, max_overflow=0)
        self.addCleanup(self.engine.dispose)
        self.schema = "direct_ci_" + uuid.uuid4().hex
        self.iid = uuid.uuid4()
        self.calls = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        with self.engine.begin() as con:
            con.execute(text(f"CREATE SCHEMA {self.schema}"))
        self.addCleanup(self.drop_schema)
        # Minimal isolated fixtures preserve the production uniqueness and
        # state constraints used by the real function; SQL is never simulated.
        ddl = """
        CREATE TABLE guard.pending_installations (
            installation_id UUID PRIMARY KEY, status TEXT NOT NULL,
            assigned_reception_id UUID, assigned_license_id TEXT,
            assigned_at TIMESTAMPTZ, updated_at TIMESTAMPTZ DEFAULT now()
        );
        CREATE TABLE guard.direct_keygate_attempts (
            installation_id UUID PRIMARY KEY, workspace_reference TEXT NOT NULL UNIQUE,
            edition TEXT, duration_months INTEGER, release_channel TEXT,
            state TEXT NOT NULL CHECK(state IN ('STARTED','CREATED','RECONCILIATION_REQUIRED')),
            keygate_license_id TEXT, updated_at TIMESTAMPTZ DEFAULT now()
        );
        CREATE TABLE guard.license_links (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), reception_id UUID UNIQUE,
            reception_number TEXT NOT NULL UNIQUE, service_device_id UUID,
            sale_kind TEXT, installation_id UUID UNIQUE,
            keygate_license_id TEXT NOT NULL UNIQUE, keygate_plan_id TEXT,
            license_key_hash TEXT NOT NULL UNIQUE, plan_code TEXT,
            duration_months INTEGER, release_channel TEXT, lifecycle TEXT
        );
        CREATE TABLE guard.workshop_grants (
            installation_id UUID PRIMARY KEY, enabled BOOLEAN NOT NULL,
            monitoring_profile TEXT, updated_at TIMESTAMPTZ DEFAULT now()
        );
        """
        with self.engine.begin() as con:
            for statement in ddl.split(";"):
                if statement.strip():
                    con.execute(self.sql(statement))
            con.execute(self.sql("INSERT INTO guard.pending_installations VALUES (:id,'WAITING',NULL,NULL,NULL,now())"), {"id": self.iid})
            con.execute(self.sql("INSERT INTO guard.workshop_grants VALUES (:id,TRUE,'OFF',now())"), {"id": self.iid})
        source = Path(__file__).resolve().parents[1] / "embedded-multiguard/app/routers/multiguard_license.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "_assign_direct_customer_license")
        env = {
            "uuid": uuid, "Any": Any, "HTTPException": HTTPError,
            "engine": self.engine, "text": self.sql, "_ensure_schema": lambda: None,
            "_normalize_link": lambda row: row, "_hash": lambda key: "hash-" + key,
            "logger": logging.getLogger("direct-postgres-ci"),
            "_keygate_create_license": self.keygate,
        }
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), "exec"), env)
        self.assign = lambda: env["_assign_direct_customer_license"](self.iid, "PRO", 6, "PILOT")

    def sql(self, query):
        return text(query.replace("guard.", self.schema + "."))

    def drop_schema(self):
        with self.engine.begin() as con:
            con.execute(text(f"DROP SCHEMA {self.schema} CASCADE"))

    def keygate(self, **kwargs):
        self.calls.append(kwargs)
        self.entered.set()
        if not self.release.wait(8):
            raise TimeoutError("Synthetic KeyGate barrier timed out")
        return {"id": "external-ci", "_plan_id": "plan-ci", "_license_key": "key-ci"}

    def state(self):
        with self.engine.connect() as con:
            pending = con.execute(self.sql("SELECT * FROM guard.pending_installations")).mappings().one()
            audit = con.execute(self.sql("SELECT * FROM guard.direct_keygate_attempts")).mappings().one()
            count = con.execute(self.sql("SELECT count(*) FROM guard.license_links")).scalar_one()
            enabled = con.execute(self.sql("SELECT enabled FROM guard.workshop_grants")).scalar_one()
        return dict(pending), dict(audit), count, enabled

    def test_concurrent_direct_creates_only_one_external_licence(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.assign)
            try:
                self.assertTrue(self.entered.wait(5))
                second = pool.submit(self.assign)
                with self.assertRaises(HTTPError) as caught:
                    second.result(timeout=5)
                self.assertEqual(caught.exception.status_code, 409)
            finally:
                self.release.set()
            first.result(timeout=5)
        pending, audit, count, enabled = self.state()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual((pending["status"], audit["state"], count, enabled),
                         ("ASSIGNED", "CREATED", 1, False))
        self.assertEqual((audit["edition"], audit["duration_months"], audit["release_channel"]),
                         ("PRO", 6, "PILOT"))

    def test_assignment_race_does_not_hold_row_lock_or_overwrite_winner(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.assign)
            try:
                self.assertTrue(self.entered.wait(5))
                with self.engine.begin() as con:
                    con.execute(text("SET LOCAL lock_timeout='2s'"))
                    con.execute(self.sql("UPDATE guard.pending_installations SET status='ASSIGNED', assigned_license_id='other-ci' WHERE installation_id=:id"), {"id": self.iid})
            finally:
                self.release.set()
            with self.assertRaises(HTTPError) as caught:
                first.result(timeout=5)
            self.assertEqual(caught.exception.status_code, 503)
        pending, audit, count, enabled = self.state()
        self.assertEqual(pending["assigned_license_id"], "other-ci")
        self.assertEqual((audit["state"], audit["keygate_license_id"], count, enabled),
                         ("RECONCILIATION_REQUIRED", "external-ci", 0, True))
        with self.assertRaises(HTTPError):
            self.assign()
        self.assertEqual(len(self.calls), 1)

    def test_real_sql_rollback_preserves_external_audit_and_service_grant(self):
        with self.engine.begin() as con:
            con.execute(self.sql("ALTER TABLE guard.workshop_grants ADD CONSTRAINT synthetic_write_failure CHECK(enabled)"))
        self.release.set()
        with self.assertRaises(HTTPError) as caught:
            self.assign()
        self.assertEqual(caught.exception.status_code, 503)
        pending, audit, count, enabled = self.state()
        self.assertEqual((pending["status"], pending["assigned_license_id"], count, enabled),
                         ("WAITING", None, 0, True))
        self.assertEqual((audit["state"], audit["keygate_license_id"]),
                         ("RECONCILIATION_REQUIRED", "external-ci"))
        with self.assertRaises(HTTPError) as retry:
            self.assign()
        self.assertEqual(retry.exception.status_code, 409)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
