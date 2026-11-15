"""MASTER110: exercise the real provision preflight with stubbed KeyGate.

No DB, network, licenses or MeshCentral are touched. This intentionally
executes the current server function up to its KeyGate activation boundary.
"""
import ast
import datetime as dt
import hashlib
import pathlib
import re
import secrets
import types
import unittest
import uuid

SOURCE = pathlib.Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
MODULE = ast.parse(SOURCE)
FUNCTION = next(n for n in MODULE.body if isinstance(n, ast.FunctionDef) and n.name == "provision")
# The code-under-test is extracted from the actual module, not reimplemented.
# KeyGate now executes inside the transaction. Extract the actual preflight
# statements preceding that transaction; the transaction and its KeyGate
# operation have separate integration/locking contract tests.
BEFORE_ACTIVATION = []
for stmt in FUNCTION.body:
    if isinstance(stmt, ast.With) and any(
        isinstance(item.context_expr, ast.Call)
        and isinstance(item.context_expr.func, ast.Attribute)
        and item.context_expr.func.attr == "begin"
        for item in stmt.items
    ):
        break
    BEFORE_ACTIVATION.append(stmt)
else:
    raise AssertionError("Cannot locate serialized activation transaction")
PRECHECK = ast.FunctionDef(name="precheck", args=FUNCTION.args, body=BEFORE_ACTIVATION + [ast.Return(value=ast.Constant(value=True))], decorator_list=[], returns=None, type_comment=None)
PRECHECK_AST = ast.fix_missing_locations(ast.Module(body=[PRECHECK], type_ignores=[]))
IID = str(uuid.uuid4())
RID = uuid.uuid4()
NOW = dt.datetime.now(dt.timezone.utc)

class HTTPException(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code

class RecoveryGuards(unittest.TestCase):
    def setUp(self):
        self.link = {
            "id": uuid.uuid4(), "installation_id": None, "device_id": None,
            "rebind_pending": True, "lifecycle": "ACTIVE",
            "reception_id": RID, "keygate_license_id": "license-test",
        }
        self.pending = {
            "status": "ASSIGNED", "assigned_reception_id": RID,
            "assigned_license_id": "license-test", "device_id": "device-X",
            "last_seen_at": NOW,
            "discovery_credential_sha256": hashlib.sha256(b"correct-secret").hexdigest(),
        }
        env = {
            "uuid": uuid, "secrets": secrets, "HTTPException": HTTPException,
            "_KEY_PATTERN": re.compile(r"^[A-Z0-9-]{4,}$"),
            "_link_by_key": lambda key: dict(self.link),
            "_normalize_link": lambda row: row,
            "_pending_installation": lambda iid: dict(self.pending) if self.pending is not None else None,
            "_hash": lambda value: hashlib.sha256(value.encode()).hexdigest(),
            "_utcnow": lambda: NOW,
        }
        exec(compile(PRECHECK_AST, "<actual-provision-precheck>", "exec"), env)
        self.check = env["precheck"]
        self.req = types.SimpleNamespace(
            provisioning_token="TEST-LICENSE", installation_id=IID,
            device_id="device-X", discovery_credential="correct-secret",
        )

    def deny(self, expected):
        with self.assertRaises(HTTPException) as ctx:
            self.check(self.req)
        self.assertEqual(ctx.exception.status_code, expected)

    def test_valid_owner_approved_recovery(self):
        self.assertTrue(self.check(self.req))

    def test_stolen_license_token_without_secret(self):
        self.req.discovery_credential = None
        self.deny(403)

    def test_wrong_discovery_secret(self):
        self.req.discovery_credential = "other-secret"
        self.deny(403)

    def test_pending_not_approved(self):
        self.pending["status"] = "WAITING"
        self.deny(409)

    def test_assigned_to_other_reception(self):
        self.pending["assigned_reception_id"] = uuid.uuid4()
        self.deny(409)

    def test_assigned_to_other_license(self):
        self.pending["assigned_license_id"] = "other-license"
        self.deny(409)

    def test_wrong_device(self):
        self.req.device_id = "other-device"
        self.deny(409)

    def test_stale_heartbeat(self):
        self.pending["last_seen_at"] = NOW - dt.timedelta(minutes=6)
        self.deny(409)

    def test_recovery_missing_pending(self):
        self.pending = None
        self.deny(403)

    def test_revoked_entitlement(self):
        self.link["lifecycle"] = "REVOKED"
        self.deny(409)

    def test_old_install_still_bound(self):
        self.link["installation_id"] = uuid.uuid4()
        self.deny(409)

    def test_new_license_original_provision_is_not_blocked(self):
        self.link["rebind_pending"] = False
        self.assertTrue(self.check(self.req))

if __name__ == "__main__":
    unittest.main()
