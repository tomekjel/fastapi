"""Regression tests for assigning a DIRECT Multi-Guard licence.

Run in the backend test environment (with app import path configured):
    PYTHONPATH=embedded-multiguard python -m unittest discover -s tests -p test_multiguard_direct_assignment_atomicity.py
No network access or production database is used.
"""
import unittest
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from app.routers import multiguard_license as mg


class SimulatedDatabase:
    """Transaction simulator: changes persist only if the block exits normally."""

    def __init__(self, fail_workshop_update=False):
        self.fail_workshop_update = fail_workshop_update
        self.state = {"status": "WAITING", "license": None, "grant": True}
        self.queries = []

    @contextmanager
    def begin(self):
        working = self.state.copy()
        db = self

        class Connection:
            def execute(self, sql, params=None):
                query = str(sql)
                db.queries.append(query)
                if "FROM guard.pending_installations" in query:
                    return Result({"status": working["status"], "assigned_license_id": working["license"]})
                if "SELECT id FROM guard.license_links" in query:
                    return Result(None)
                if "INSERT INTO guard.license_links" in query:
                    return Result({"keygate_license_id": "FAKE-LICENSE", "plan_code": "multi_guard_pro"})
                if "UPDATE guard.pending_installations" in query:
                    working["status"] = "ASSIGNED"
                    working["license"] = "FAKE-LICENSE"
                if "UPDATE guard.workshop_grants" in query:
                    if db.fail_workshop_update:
                        raise RuntimeError("synthetic SQL error during grant revocation")
                    working["grant"] = False
                return Result(None)

        try:
            yield Connection()
        except Exception:
            raise
        else:
            self.state = working


class Result:
    def __init__(self, value):
        self.value = value

    def first(self):
        return self.value

    def one(self):
        return self.value

    def mappings(self):
        return self


class DirectAssignmentAtomicityTests(unittest.TestCase):
    def run_assignment(self, database):
        with (
            patch.object(mg, "engine", database),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", return_value={
                "id": "FAKE-LICENSE", "_plan_id": "FAKE-PLAN", "_license_key": "FAKE-KEY"
            }),
            patch.object(mg, "_normalize_link", side_effect=lambda link: link),
        ):
            return mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")

    def test_assigns_paid_rights_and_revokes_service_grant_together(self):
        db = SimulatedDatabase()
        result = self.run_assignment(db)
        self.assertEqual(result["keygate_license_id"], "FAKE-LICENSE")
        self.assertEqual(db.state, {"status": "ASSIGNED", "license": "FAKE-LICENSE", "grant": False})

    def test_keygate_failure_does_not_assign_local_rights(self):
        db = SimulatedDatabase()
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", side_effect=RuntimeError("synthetic KeyGate outage")),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic KeyGate outage"):
                mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")
        self.assertEqual(db.state, {"status": "WAITING", "license": None, "grant": True})
        self.assertFalse(any("INSERT INTO guard.license_links" in q for q in db.queries))

    def test_sql_failure_after_external_creation_requires_reconciliation(self):
        """Document cross-system failure: SQL rollback cannot undo KeyGate."""
        db = SimulatedDatabase(fail_workshop_update=True)
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", return_value={
                "id": "EXTERNAL-ORPHAN", "_plan_id": "FAKE-PLAN", "_license_key": "FAKE-KEY"
            }) as keygate,
        ):
            with self.assertRaises(mg.HTTPException) as failure:
                mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")
        self.assertEqual(failure.exception.status_code, 503)
        self.assertIn("KeyGate", failure.exception.detail)
        keygate.assert_called_once()
        self.assertEqual(db.state["status"], "WAITING")
        self.assertIsNone(db.state["license"])
        # External licence exists in this scenario despite SQL rollback.
        # This is a documented release blocker until reconciliation is implemented.

    def test_sql_failure_rolls_back_pending_assignment(self):
        db = SimulatedDatabase(fail_workshop_update=True)
        with self.assertRaises(mg.HTTPException) as failure:
            self.run_assignment(db)
        self.assertEqual(failure.exception.status_code, 503)
        self.assertEqual(db.state, {"status": "WAITING", "license": None, "grant": True})
        self.assertTrue(any("UPDATE guard.workshop_grants" in q for q in db.queries))


if __name__ == "__main__":
    unittest.main()
