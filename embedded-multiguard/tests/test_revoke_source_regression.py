"""Static regression checks for OWNER's KeyGate revoke transaction.

This catches accidental variable shadowing in the external revoke verification
path before the code reaches production. No production DB/network access.
"""
import ast
from pathlib import Path

source=Path(__file__).resolve().parents[1] / "app/routers/multiguard_license.py"
tree=ast.parse(source.read_text(encoding="utf-8"))
fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
        and node.name=="_revoke_owner_license")
names={node.id for node in ast.walk(fn) if isinstance(node,ast.Name)}
assert "keygate_state" in names, "KeyGate verification must retain its own state"
assert "remote" not in names, "Do not reference or shadow remote in revoke flow"
assert any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
           and node.func.attr=="revoke_share" for node in ast.walk(fn)), (
           "Revocation must keep Mesh share invalidation")
service=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
             and node.name=="_set_workshop_grant")
disable=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
             and node.name=="owner_disable_workshop")
for fn in (service,disable):
    sql_literals=[
        node.value for node in ast.walk(fn)
        if isinstance(node,ast.Constant) and isinstance(node.value,str)
    ]
    assert any("workshop_remote_sessions" in q
               and "mesh_public_id IS NOT NULL" in q for q in sql_literals), (
        f"{fn.name} must check leftover Mesh share links even after session status changes")

# License-only checks: never downgrade a KeyGate scope failure into a
# duplicate issuance and never change channels on revoked licences.
request=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
             and node.name=="_keygate_request")
channel=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
             and node.name=="set_reception_release_channel")
assert any(isinstance(n,ast.Constant) and isinstance(n.value,str)
           and "PRODUCT_SCOPE_MISMATCH" in n.value for n in ast.walk(request))
assert any(isinstance(n,ast.Compare) and
           any(isinstance(c,ast.Constant) and c.value=="ACTIVE" for c in n.comparators)
           for n in ast.walk(channel))
print("PASS: revoke and licence-only fail-closed guards")
