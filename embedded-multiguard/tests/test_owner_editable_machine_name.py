#!/usr/bin/env python3
"""Isolated checks for the OWNER's single, editable computer display name.

Does not import the production FastAPI app, require PostgreSQL, or mutate data.
All tests operate on the actual router functions extracted with Python AST.
"""
from __future__ import annotations

import ast
import html
import re
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
devices_src = (ROOT / "app/routers/multiguard_panel_devices.py").read_text(encoding="utf-8")
runtime_src = (ROOT / "app/routers/multiguard_runtime.py").read_text(encoding="utf-8")
license_src = (ROOT / "app/routers/multiguard_license.py").read_text(encoding="utf-8")
theme_src = (ROOT / "app/routers/multiguard_panel_theme.py").read_text(encoding="utf-8")

tree = ast.parse(devices_src)
fn_names = {"owner_detected_name", "owner_name_form"}
functions = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name in fn_names]
assert len(functions) == 2, "Expected the two implemented display-name functions"
scope = {
    "Any": Any,
    "html": html,
    "time": time,
    "uuid": uuid,
    "_csrf_token": lambda hour: "dummy_csrf_" + str(hour),
}
exec(compile(ast.Module(body=functions, type_ignores=[]), "<owner-machine-name>", "exec"), scope)
detected = scope["owner_detected_name"]
form = scope["owner_name_form"]
iid = uuid.UUID("f6c88473-7a0a-4451-b03a-d2dc6885f41f")

source_info = {
    "manufacturer": "ASUSTeK COMPUTER INC.",
    "model": "ROG Zephyrus Duo 16 GX650PZ_GX650PZ",
    "hostname": "ROG-ASUS-1",
}
default_name = detected(source_info)
assert default_name == "ASUSTeK COMPUTER INC. ROG Zephyrus Duo 16 GX650PZ_GX650PZ"
assert detected({"hostname": "OFFICE-01"}) == "OFFICE-01"
assert detected({}) == "Komputer bez nazwy"

def entered_value(markup: str) -> str:
    match = re.search(r'name="friendly_name" maxlength="420" value="([^"]*)"', markup)
    assert match, "Input must be prefilled with currently visible display name"
    return html.unescape(match.group(1))

fresh_form = form(iid, "", return_to="pending", detected_name=default_name)
assert entered_value(fresh_form) == default_name
assert "Edytuj nazwę komputera" in fresh_form

# OWNER can put 'Multi-Servis' wherever they wish, not only at the end.
preferred = "Multi-Servis ASUS ROG Duo 16"
saved_form = form(iid, preferred, return_to="device", detected_name=default_name)
assert entered_value(saved_form) == preferred
assert "MULTI-SERVIS / NAZWA KOMPUTERA" in saved_form
assert "Puste pole przywraca nazwę automatyczną" in fresh_form

# Quotation marks or HTML from a supplied alias cannot escape the value
# attribute to inject another input/handler.
injected = 'Multi-Servis" onfocus="alert(1) <script>'
malicious_form = form(iid, injected, return_to="device", detected_name=default_name)
assert entered_value(malicious_form) == injected
assert '&quot; onfocus=&quot;' in malicious_form
assert '<script>' not in malicious_form

# No 120-character database cap: a very long detected name should remain
# editable, including the extra words supplied by the OWNER.
long_detected = "ASUSTeK " + ("ROG-" * 45) + "Zephyrus Duo"
assert len(long_detected) > 120
assert entered_value(form(iid, "", return_to="pending", detected_name=long_detected)) == long_detected
assert "VARCHAR(420)" in devices_src
assert "ALTER COLUMN friendly_name TYPE VARCHAR(420)" in devices_src
assert "len(clean) > 420" in devices_src

# One display name across the queue, computer details and assigned fleet.
assert "display_name = owner_friendly_name(iid) or detected_name" in runtime_src
assert '<b class="owner-machine-display pending-name-text" title="{safe_name}">{safe_name}</b>' in runtime_src
assert 'class="pending-computers-table"' in runtime_src
assert 'class="pending-edit-name"' in runtime_src
assert 'pending-name-dialog-{safe_id}' in runtime_src
assert 'name="friendly_name"' in runtime_src
assert 'maxlength="420" value="{safe_name}"' in runtime_src
assert 'name="return_to" value="computers"' in runtime_src
assert '_panel_h(name)} ·' not in runtime_src
assert 'detected_name=owner_detected_name(row)' in runtime_src
assert "display_name = stored_name or detected_name" in license_src
assert 'detected_name=detected_name' in license_src
assert 'Własna nazwa: ' not in license_src
assert 'owner-machine-display {display:block;' in theme_src
assert 'overflow-wrap:anywhere' in theme_src

print("PASS: editable OWNER computer name starts with full hardware name.")
print("PASS: OWNER replacement can be anywhere in the name; detected hardware is preserved.")
print("PASS: safe form escaping, long names, and consistent single-name display.")
