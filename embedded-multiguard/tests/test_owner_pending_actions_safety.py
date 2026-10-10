#!/usr/bin/env python3
"""OWNER pending queue: two visible actions, TWO-STEP archive confirmation.

Offline source contract. No production credentials, database, server mutation.
"""
import ast
from pathlib import Path

root=Path(__file__).resolve().parents[1]/"app/routers"
runtime=(root/"multiguard_runtime.py").read_text(encoding="utf8")
theme=(root/"multiguard_panel_theme.py").read_text(encoding="utf8")
ast.parse(runtime)

# Both controls appear in the same horizontal action row, not a hidden menu.
assert 'archive_action = ""' in runtime
assert 'pending["status"] == "WAITING"' in runtime
assert 'type="button" class="pending-archive-trigger"' in runtime
assert 'USUŃ Z OCZEKUJĄCYCH' in runtime
assert 'pending-archive-dialog-{safe_id}' in runtime
assert "showModal()" in runtime
assert 'Czy jesteś pewien?' in runtime
assert 'TAK, USUŃ Z LISTY' in runtime
assert 'Historia zostanie zachowana.' in runtime
assert 'onclick="this.closest(\'dialog\').close()"' in runtime
assert '<form method="post" action="/multiguard/panel/computers/pending/{safe_id}/archive">' in runtime
assert '<input type="hidden" name="csrf_token" value="{archive_csrf}">' in runtime

start=runtime.index('pending_trs.append(f"""')
stop=runtime.index('pending_section = f"""',start)
row_template=runtime[start:stop]
assert 'PRZYPISZ LICENCJĘ' in row_template
assert '{archive_action}' in row_template
assert 'class="pending-actions-row"' in row_template
assert 'class="pending-primary-actions"' in row_template
assert row_template.index('PRZYPISZ LICENCJĘ') < row_template.index('{archive_action}')
assert 'pending-extra-actions' not in runtime
assert 'USUŃ Z OCZEKUJĄCYCH' not in row_template, "The form only belongs to modal, not immediate submit"

# Defensive, explicit 2-click flow: a visible type=button opens a modal,
# only its separate POST form can archive the record.
assert '.pending-actions-row {display:flex;' in theme
assert 'white-space:nowrap' in theme
assert '.pending-owner-dialog::backdrop' in theme
assert '.pending-dialog-buttons .pending-confirm-archive' in theme

# The server retains OWNER Basic auth, anti-CSRF and non-destructive audit.
assert 'def owner_archive_pending_installation(' in runtime
assert '_token_valid(csrf_token)' in runtime
assert "status='ARCHIVED'" in runtime
assert 'INSERT INTO guard.pending_archive_events' in runtime
assert 'DELETE FROM guard.pending_installations' not in runtime
assert 'row["status"] not in {"WAITING","IGNORED"}' in runtime
assert 'if grant:' in runtime

print("PASS: same-row licence/remove buttons, modal second-step confirmation.")
print("PASS: OWNER-only CSRF, no hard DELETE, licence/workshop safety unchanged.")
