#!/usr/bin/env python3
"""MASTER 1.5: fix only legacy target_mode CHECK for signed OWNER Standard/Pro.
Preserve the entire original CHECK expression and add only STANDARD and PRO.
No licence, session, Mesh, Windows, or notification mutations.
"""
from __future__ import annotations

import os
import re
import sys

from sqlalchemy import text
from app.database import engine

SCHEMA="guard"
TABLE="workshop_profile_transitions"
NAME="workshop_profile_transitions_target_mode_check"

def main() -> None:
    if os.geteuid()!=0:
        raise RuntimeError("ROOT_REQUIRED")
    with engine.begin() as db:
        # Serialize concurrent migrations, but do not alter application rows.
        db.execute(text("LOCK TABLE guard.workshop_profile_transitions IN ACCESS EXCLUSIVE MODE"))
        old=db.execute(text("""
            SELECT c.contype, c.convalidated, pg_get_expr(c.conbin,c.conrelid) AS predicate
            FROM pg_constraint c
            JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname=:schema AND t.relname=:table AND c.conname=:name
        """),{"schema":SCHEMA,"table":TABLE,"name":NAME}).mappings().all()
        if len(old)!=1 or old[0]["contype"]!="c" or not old[0]["convalidated"]:
            raise RuntimeError("EXPECTED_VALIDATED_TARGET_CHECK_NOT_FOUND")
        expr=str(old[0]["predicate"])
        # This change is deliberately only for the prior target_mode CHECK.
        if (not 12<len(expr)<4096 or not re.search(r"\btarget_mode\b",expr)
            or ";" in expr or "--" in expr or "/*" in expr):
            raise RuntimeError("UNEXPECTED_CHECK_EXPRESSION")
        print("EXISTING_CHECK:",expr)
        # Scope to exact approved OWNER target profiles and retain all older values.
        new_expr="("+expr+") OR (target_mode IN ('STANDARD','PRO'))"
        db.execute(text(
            'ALTER TABLE guard.workshop_profile_transitions '
            'DROP CONSTRAINT workshop_profile_transitions_target_mode_check'
        ))
        db.execute(text(
            'ALTER TABLE guard.workshop_profile_transitions '
            'ADD CONSTRAINT workshop_profile_transitions_target_mode_check '
            'CHECK ('+new_expr+')'
        ))
        verified=db.execute(text("""
            SELECT c.convalidated, pg_get_expr(c.conbin,c.conrelid) AS predicate
            FROM pg_constraint c
            JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname='guard' AND t.relname='workshop_profile_transitions'
              AND c.conname='workshop_profile_transitions_target_mode_check'
        """)).mappings().one()
        if not verified["convalidated"] or "STANDARD" not in verified["predicate"] or "PRO" not in verified["predicate"]:
            raise RuntimeError("TARGET_CHECK_POST_VERIFY_FAILED")
        print("PASS: original allowed values retained, signed OWNER STANDARD and PRO admitted")
        print("PASS: PostgreSQL CHECK validated and committed atomically")
        print("PASS: no changes to licences, session rows, Mesh or Windows services")
    print("MASTER15_OWNER_PROFILE_TARGET_MODE_CHECK_FIX_PASS")

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("MASTER15_TARGET_MODE_STOP",type(exc).__name__,str(exc)[:250],file=sys.stderr)
        raise SystemExit(1)
