#!/usr/bin/env python3
"""One-time safe migration: forbid new perpetual OWNER license choices.

Execute on LXC 103 in /opt/multiservis. No database writes. Existing grants
are preserved. The migration is idempotent and aborts if code differs.
"""
from pathlib import Path
from datetime import datetime, timezone
import ast
import shutil

p = Path("app/routers/multiguard_license.py")
s = p.read_text(encoding="utf-8")
old = 'if choice not in ("KEEP", "3", "6", "12", "CALENDAR", "PERPETUAL"):'
new = 'if choice not in ("KEEP", "3", "6", "12", "CALENDAR"):'
if old in s:
    if s.count(old) != 1:
        raise SystemExit("ABORT: unexpected number of term validators")
    updated = s.replace(old, new)
elif new in s:
    updated = s
else:
    raise SystemExit("ABORT: expected term validator absent")
ast.parse(updated, filename=str(p))

# Remove perpetual choice only inside HTML <option> or button controls, never
# rewrite the broader licensing logic based on an unreviewed global replace.
import re
matches = list(re.finditer(r'<option\b[^>]*\bvalue\s*=\s*["\']PERPETUAL["\'][^>]*>.*?</option>', updated, re.I | re.S))
if len(matches) > 2:
    raise SystemExit("ABORT: unexpected perpetual option count")
updated = re.sub(r'<option\b[^>]*\bvalue\s*=\s*["\']PERPETUAL["\'][^>]*>.*?</option>', '', updated, flags=re.I | re.S)
ast.parse(updated, filename=str(p))
if updated != s:
    backup = p.with_name(p.name + ".backup-no-perpetual-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    shutil.copy2(p, backup)
    p.write_text(updated, encoding="utf-8")
    print("PATCH_OK backup:", backup)
else:
    print("ALREADY_APPLIED")
print("VALIDATOR_PERPETUAL_REMOVED:", old not in updated)
print("NO DATABASE OR SERVICE CHANGES")
