"""Read-only tests of the production paid-remote overlay, no SQL or Mesh."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"stage_paid_remote_mode_gate_v44.py"
spec=importlib.util.spec_from_file_location("paid_gate",SCRIPT)
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

UPSTREAM=(ROOT/"app/routers/multiguard_remote.py").read_text()

def legacy_fixture():
    src=UPSTREAM
    for name in ("_has_verified_remote_pro","_has_verified_service_remote_pro"):
        n=gate.functions(src)[name]
        start=min([n.lineno]+[d.lineno for d in n.decorator_list])
        lines=src.splitlines(keepends=True)
        src="".join(lines[:start-1]+lines[n.end_lineno:])
    names=("agent_remote_poll","agent_remote_decision","create_remote_session",
           "remote_session_connect")
    # Follow all source callsites, restoring the older unverified gate.
    for name in gate.functions(src):
        if name.startswith("panel_") or name in names:
            if "_has_verified_remote_pro(connection, " not in src:
                continue
            start,end=gate.extract(src,name)
            lines=src.splitlines(keepends=True)
            chunk="".join(lines[start-1:end]).replace(
                "_has_verified_remote_pro(connection, ",
                "_has_active_remote_pro("
            )
            src=gate.rewrite(src,name,chunk)
    # Production has a fifth route absent in the branch snapshot.
    # Its paid check is nested in validate(db), not in an outer "connection".
    src += (
        "\ndef agent_session_mesh_enroll(body):\n"
        "    def validate(db, lock=False):\n"
        "        installation = {'id': 1}\n"
        "        if not _has_active_remote_pro(installation, now):\n"
        "            raise RuntimeError('DENIED')\n"
        "    with engine.begin() as db:\n"
        "        validate(db, True)\n"
    )
    ast.parse(src)
    return src

class PaidRemoteOverlayTests(unittest.TestCase):
    def test_old_code_gains_in_transaction_owner_mode_gate(self):
        source,calls=gate.paid_remote_overlay(legacy_fixture())
        ast.parse(source)
        self.assertIn("agent_remote_poll",calls)
        self.assertIn("create_remote_session",calls)
        self.assertIn("FOR SHARE",source)
        self.assertIn('!= "CLIENT"',source)
        self.assertIn("and paid[\"valid_until\"] is not None",source)
        self.assertIn("def _owner_verified_service_remote(",source)
        self.assertIn("return False",source)
        self.assertEqual(set(calls), {
            "agent_session_mesh_enroll", "agent_remote_poll",
            "agent_remote_decision", "create_remote_session",
            "remote_session_connect",
        })
        for name in calls:
            start,end=gate.extract(source,name)
            body="".join(source.splitlines(keepends=True)[start-1:end])
            conn="db" if name=="agent_session_mesh_enroll" else "connection"
            self.assertIn("_owner_verified_paid_remote("+conn+", ",body)
            self.assertNotIn("_has_active_remote_pro(",body)
        self.assertIn("FOR SHARE",source)
        # Five connection call sites plus one helper definition.
        self.assertEqual(
            source.count("_owner_verified_paid_remote(connection, "),6
        )
        self.assertEqual(source.count("_owner_verified_paid_remote(db, "),1)

    def test_fail_closed_on_duplicate_or_unknown_callsite(self):
        with self.assertRaises(RuntimeError):
            gate.paid_remote_overlay(UPSTREAM)
        invalid=legacy_fixture()+"\ndef unexpected_bypass(i, now):\n    return _has_active_remote_pro(i, now)\n"
        with self.assertRaises(RuntimeError):
            gate.paid_remote_overlay(invalid)

if __name__=="__main__":
    unittest.main()
