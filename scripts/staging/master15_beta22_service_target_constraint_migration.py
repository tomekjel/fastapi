#!/usr/bin/env python3
"""MASTER 1.5 beta.22: extend the exact validated OWNER target CHECK for
SERVICE (dormant staging only). Keep all previous allowed target modes.

This file is staged for an explicitly guarded production deployment. It is
NOT executed by GitHub Actions. Always keep signed Windows receipt gates.
"""
from sqlalchemy import text
from app.database import engine

TABLE = "guard.workshop_profile_transitions"
CHECK = "workshop_profile_transitions_target_mode_check"

def apply():
    with engine.begin() as db:
        db.execute(text("LOCK TABLE guard.workshop_profile_transitions IN ACCESS EXCLUSIVE MODE"))
        row=db.execute(text("""
            SELECT c.contype,c.convalidated,pg_get_expr(c.conbin,c.conrelid) AS predicate
            FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname='guard' AND t.relname='workshop_profile_transitions'
              AND c.conname='workshop_profile_transitions_target_mode_check'
        """)).mappings().one()
        predicate=str(row["predicate"])
        if (row["contype"]!="c" or not row["convalidated"]
            or "target_mode" not in predicate or ";" in predicate
            or "--" in predicate or "/*" in predicate or len(predicate)>2048):
            raise RuntimeError("UNEXPECTED_OWNER_TARGET_CHECK")
        # Original predicate retained in full; only a new constant SERVICE
        # allowed for already authenticated and signed OWNER target reservations.
        if "'SERVICE'" in predicate:
            print("PASS_ALREADY_ALLOWS_SERVICE")
            return
        updated="("+predicate+") OR target_mode = 'SERVICE'"
        db.execute(text("ALTER TABLE guard.workshop_profile_transitions DROP CONSTRAINT "+CHECK))
        db.execute(text("ALTER TABLE guard.workshop_profile_transitions ADD CONSTRAINT "+CHECK+" CHECK ("+updated+")"))
        after=db.execute(text("""
            SELECT convalidated,pg_get_expr(conbin,conrelid) AS predicate
            FROM pg_constraint WHERE conname=:name AND conrelid=:tbl::regclass
        """),{"name":CHECK,"tbl":TABLE}).mappings().one()
        assert after["convalidated"] and "'SERVICE'" in after["predicate"]
    print("MASTER15_BETA22_SIGNED_SERVICE_TARGET_CHECK_PASS")

if __name__=="__main__":
    apply()
