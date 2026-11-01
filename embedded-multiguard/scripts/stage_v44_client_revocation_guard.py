#!/usr/bin/env python3
"""Fail-closed surgical staging of signed Service revocation on OWNER CLIENT discovery.

No automatic production writes, no API restart, no KeyGate or Mesh calls.
Source-only preflight: outputs a candidate and tests invariants. Optional
--apply requires explicit operator action and creates a backup beforehand.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
from pathlib import Path
import shutil
from datetime import datetime,timezone

TARGET=Path("/opt/multiservis/app/routers/multiguard_license.py")
NAME="_client_mode_revocation_lease"

def functions(s):
    return {n.name:n for n in ast.parse(s).body
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def source_function(s,name):
    n=functions(s)[name]
    lines=s.splitlines(keepends=True)
    return "".join(lines[n.lineno-1:n.end_lineno])

def stage(live,reference):
    defs=functions(live)
    if "discovery_assignment" not in defs or "_signed_workshop_grant" not in defs:
        raise ValueError("BLOCK: unexpected production discovery implementation")
    if NAME not in functions(reference):
        raise ValueError("BLOCK: reference missing signed revocation")
    discovery=source_function(live,"discovery_assignment")
    # Changing the handler without comparing its actual semantics is dangerous.
    # Require the original WAITING response to be an explicit, unique anchor.
    exact='''        return {
            "assigned": False,
            "status": "WAITING",
            "serverTime": _iso(_utcnow()),
        }'''
    protected='''        return {
            "assigned": False,
            "status": "WAITING",
            **_client_mode_revocation_lease(pending, selected_mode),
            "serverTime": _iso(_utcnow()),
        }'''
    if NAME in defs:
        raise ValueError("ALREADY_PRESENT: do not overwrite existing function")
    # Only safe when effective OWNER mode is rechecked in this same handler.
    if "_owner_effective_entitlement_mode(" not in discovery:
        raise ValueError("BLOCK: selected OWNER mode is not read by discovery")
    if discovery.count(exact)!=1:
        raise ValueError("BLOCK: waiting-response shape differs; human review required")
    original_body=source_function(live,"discovery_assignment")
    upgraded=original_body.replace(exact,protected,1)
    if upgraded==original_body:
        raise ValueError("BLOCK: no protected waiting branch")
    if 'def _client_mode_revocation_lease' not in reference:
        raise ValueError("BLOCK: missing helper")
    # Anchor insertion directly before discovery ensures no other functions move.
    helper=source_function(reference,NAME)
    pos=live.index(original_body)
    candidate=live[:pos]+helper+"\n\n"+upgraded+live[pos+len(original_body):]
    before=functions(live)
    after=functions(candidate)
    if set(after)!=set(before)|{NAME}:
        raise ValueError("BLOCK: unexpected source structure")
    for name in before:
        if name!="discovery_assignment":
            if ast.dump(before[name],include_attributes=False)!=ast.dump(after[name],include_attributes=False):
                raise ValueError("BLOCK: another function changed: "+name)
    compile(candidate,str(TARGET),"exec")
    return candidate

def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--target",type=Path,default=TARGET)
    cli.add_argument("--reference",required=True,type=Path)
    cli.add_argument("--output",type=Path)
    args=cli.parse_args()
    original=args.target.read_text(encoding="utf-8")
    reference=args.reference.read_text(encoding="utf-8")
    try:
        candidate=stage(original,reference)
    except ValueError as exc:
        print(str(exc))
        return 2
    print("STAGE PASS: CLIENT discovery signed revocation guard")
    print("ORIGINAL_SHA256:",hashlib.sha256(original.encode()).hexdigest())
    print("CANDIDATE_SHA256:",hashlib.sha256(candidate.encode()).hexdigest())
    print("NO PRODUCTION WRITES / NO KEYGATE / NO MESH")
    if args.output:
        if args.output.resolve()==args.target.resolve():
            raise ValueError("BLOCK: do not overwrite live file via staging")
        args.output.write_text(candidate,encoding="utf-8")
        print("CANDIDATE:",args.output)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
