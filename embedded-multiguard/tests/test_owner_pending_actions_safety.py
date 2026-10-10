#!/usr/bin/env python3
"""OWNER UX safety checks — primary licence and manual archival are separate.

Run without the server, credentials, database or production mutations.
"""
import ast
from pathlib import Path
root=Path(__file__).resolve().parents[1]/"app/routers"
runtime=(root/"multiguard_runtime.py").read_text(encoding="utf8")
theme=(root/"multiguard_panel_theme.py").read_text(encoding="utf8")
ast.parse(runtime)

assert 'archive_menu = ""' in runtime
assert '<details class="pending-extra-actions">' in runtime
assert '<summary aria-label="Dodatkowe działania dla ' in runtime
assert '⋯ WIĘCEJ</summary>' in runtime
assert '<div class="pending-extra-content">' in runtime
assert 'USUŃ Z OCZEKUJĄCYCH</button></form></div></details>' in runtime
assert 'onsubmit="return confirm(&quot;Na pewno usunąć ten komputer ' in runtime
assert '<input type="hidden" name="csrf_token" value="' in runtime

start=runtime.index('pending_trs.append(f"""')
stop=runtime.index('pending_section = f"""',start)
row_template=runtime[start:stop]
assert 'PRZYPISZ LICENCJĘ' in row_template
assert '{archive_menu}' in row_template
assert 'archive_form' not in row_template
assert row_template.index('PRZYPISZ LICENCJĘ') < row_template.index('{archive_menu}')
assert 'class="pending-primary-actions"' in row_template
assert 'USUŃ Z OCZEKUJĄCYCH' not in row_template, "Delete must be hidden from the row's default view"

assert ".pending-extra-actions>summary:focus-visible" in theme
assert ".pending-extra-content" in theme
assert "margin-top:16px" in theme

# Keep archive auth + soft-delete guard; never allow accidental hard DELETE.
assert 'def owner_archive_pending_installation(' in runtime
assert '_token_valid(csrf_token)' in runtime
assert "status='ARCHIVED'" in runtime
assert 'INSERT INTO guard.pending_archive_events' in runtime
assert 'DELETE FROM guard.pending_installations' not in runtime

print("PASS: deletion is hidden behind a separate menu and confirmation.")
print("PASS: primary licence action and CSRF-protected soft archive stay distinct.")
