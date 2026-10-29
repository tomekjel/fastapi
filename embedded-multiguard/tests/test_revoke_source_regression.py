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
print("PASS: revoke KeyGate verification does not shadow remote sessions")
