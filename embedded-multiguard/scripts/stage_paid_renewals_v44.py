#!/usr/bin/env python3
"""Add a real OWNER paid-renewal page to production V4.4.

One narrow, additive deployment: no changes to paid keys, licence rows,
MeshCentral, selected-mode flags, or original V4.4 table layout. Enables an
authenticated, CSRF-protected screen for extending any ACTIVE CLIENT licence
by +3/+6/+12 *calendar months*. Reuses the existing idempotent KeyGate
absolute-expiration engine and requires explicit payment confirmation.

DRY RUN by default. --apply makes a backup, checks no active remote sessions,
deploys one file atomically, restarts FastAPI, verifies OWNER auth and rolls
back on failure. Refuses unexpected production source shapes.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = Path("/opt/multiservis")
ROUTERS = ROOT / "app/routers"
LICENSE = ROUTERS / "multiguard_license.py"
NEW_GET = "panel_owner_paid_renewals"
NEW_POST = "panel_owner_paid_renewals_post"
URL = "/multiguard/panel/paid-renewals"

ROUTES = r'''
@router.get("/multiguard/panel/paid-renewals", response_class=HTMLResponse)
def panel_owner_paid_renewals(
    done: str = "",
    _: None = Depends(_panel_auth),
):
    """Active paid CLIENT licences: extensions by calendar months only."""
    from datetime import timezone
    from zoneinfo import ZoneInfo
    _ensure_schema()
    with engine.connect() as con:
        links = con.execute(text("""
            SELECT l.id, l.installation_id, l.reception_number,
                   l.plan_code, l.lifecycle, l.sale_kind, l.valid_until,
                   COALESCE(lbl.friendly_name,'') AS friendly_name
            FROM guard.license_links l
            LEFT JOIN guard.owner_installation_labels lbl
              ON lbl.installation_external_id=l.installation_id
            WHERE l.lifecycle='ACTIVE' AND l.valid_until>now()
                  AND l.installation_id IS NOT NULL
            ORDER BY l.valid_until ASC, l.id ASC
            LIMIT 500
        """)).mappings().all()
        eligible = [
            row for row in links
            if _owner_effective_entitlement_mode(con, row["installation_id"]) == "CLIENT"
        ]
    csrf = _panel_escape(_workshop_csrf())
    rows = []
    for link in eligible:
        lid = _panel_escape(str(link["id"]))
        name = _panel_escape(str(link["friendly_name"] or
            link["reception_number"] or str(link["installation_id"])[:8]))
        edition = "Pro" if link["plan_code"] == "multi_guard_pro" else "Standard"
        date_display = _panel_escape(
            link["valid_until"].astimezone(ZoneInfo("Europe/Warsaw"))
            .strftime("%d.%m.%Y %H:%M")
        )
        expected = _panel_escape(_iso(link["valid_until"]))
        operation = _panel_escape(str(uuid.uuid4()))
        rows.append(f"""
          <tr>
            <td>{name}<small>{_panel_escape(str(link["installation_id"])[:8])}…</small></td>
            <td>{edition}</td>
            <td>{date_display}</td>
            <td>
              <form method="post" action="/multiguard/panel/paid-renewals/{lid}/extend"
                    onsubmit="return confirm('Potwierdzasz płatność i przedłużenie licencji?')">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <input type="hidden" name="operation_id" value="{operation}">
                <input type="hidden" name="expected_end" value="{expected}">
                <select name="months" required aria-label="Przedłuż licencję">
                  <option value="3">+3 miesiące</option>
                  <option value="6">+6 miesięcy</option>
                  <option value="12">+12 miesięcy</option>
                </select>
                <label><input type="checkbox" name="payment_confirmed"
                   value="yes" required> Płatność otrzymana</label>
                <button type="submit">Przedłuż</button>
              </form>
            </td>
          </tr>""")
    notice = ('<p><strong>Przedłużenie zapisane w KeyGate.</strong> '
              'Zaktualizowana data znajduje się poniżej.</p>'
              if done == "yes" else "")
    content = ("""
      <section class="card">
        <a href="/multiguard/panel/licenses-grid">← Wróć do tabeli licencji</a>
        <h1>Przedłużenia licencji Standard / Pro</h1>
        <p>Nowe miesiące są dodawane do dotychczasowej daty wygaśnięcia,
           nie do dzisiejszej daty. Klucze KeyGate i edycje pozostają te same.</p>
      """ + notice + """
      <div class="table-wrap"><table>
      <thead><tr><th>Komputer</th><th>Edycja</th>
      <th>Aktualna ważność</th><th>Przedłużenie i płatność</th></tr></thead>
      <tbody>""" + "".join(rows) + """</tbody></table></div>
      """ + ("<p>Brak aktywnych licencji klienta do przedłużenia.</p>"
             if not rows else "") + """
      </section>""")
    return HTMLResponse(_panel_html(content), headers={
        "Cache-Control": "private, no-store",
    })


@router.post("/multiguard/panel/paid-renewals/{link_id}/extend")
def panel_owner_paid_renewals_post(
    link_id: uuid.UUID,
    operation_id: uuid.UUID = Form(...),
    expected_end: str = Form(...),
    months: int = Form(...),
    payment_confirmed: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    """Stale-write-safe; no change to edition, service mode, or KeyGate ID."""
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    from datetime import datetime

    if not _token_valid(csrf_token):
        raise HTTPException(403, "Formularz wygasł lub jest nieprawidłowy.")
    if payment_confirmed != "yes":
        raise HTTPException(400, "Potwierdź otrzymanie płatności.")
    if months not in (3, 6, 12):
        raise HTTPException(400, "Dozwolone jest przedłużenie o 3, 6 lub 12 miesięcy.")
    try:
        original_end = datetime.fromisoformat(expected_end.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy dotychczasowy termin.") from exc
    if original_end.tzinfo is None:
        raise HTTPException(400, "Termin licencji musi mieć strefę czasową.")

    _ensure_schema()
    with engine.connect() as con:
        link = con.execute(text("""
            SELECT id, installation_id, plan_code, lifecycle, valid_until
            FROM guard.license_links
            WHERE id=:id
        """), {"id": link_id}).mappings().one_or_none()
        if not link or not link["installation_id"]:
            raise HTTPException(404, "Nie znaleziono licencji przypisanej do komputera.")
        if _owner_effective_entitlement_mode(con, link["installation_id"]) != "CLIENT":
            raise HTTPException(409, "Komputer nie jest w trybie licencji klienta.")
        if link["lifecycle"] != "ACTIVE":
            raise HTTPException(409, "Przedłużać można tylko aktywne licencje.")
        if link["valid_until"] != original_end:
            raise HTTPException(409, "Termin zmienił się. Odśwież stronę.")

    _extend_active_license(
        link["installation_id"], months, operation_id,
        source="WEB", payment_confirmed=True,
        by_installation=True, expected_end=original_end,
    )
    return RedirectResponse(
        "/multiguard/panel/paid-renewals?done=yes",
        status_code=303,
        headers={"Cache-Control": "private, no-store"},
    )
'''

def names(source: str):
    return {
        n.name: n for n in ast.parse(source).body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

def function_text(src: str, name: str):
    node = names(src).get(name)
    if node is None:
        raise RuntimeError("Brak istniejącej funkcji: " + name)
    lines = src.splitlines(keepends=True)
    return "".join(lines[node.lineno-1:node.end_lineno])

def insert_function(src, name, replacement):
    node = names(src).get(name)
    if node is None or node.decorator_list:
        raise RuntimeError("Nieoczekiwany kształt funkcji: " + name)
    lines = src.splitlines(keepends=True)
    return ("".join(lines[:node.lineno-1]) + replacement.rstrip() + "\n" +
            "".join(lines[node.end_lineno:]))

def update_extension_engine(src: str):
    body = function_text(src, "_extend_active_license")
    parsed = ast.parse(src)
    node = names(src)["_extend_active_license"]
    args = [a.arg for a in node.args.args + node.args.kwonlyargs]
    if "expected_end" in args:
        if "if expected_end is not None and end != expected_end:" not in body:
            raise RuntimeError("Niesprawdzony warunek expected_end w produkcyjnym helperze.")
        return src, False
    signature = "    by_installation: bool = False,\n"
    if body.count(signature) != 1:
        raise RuntimeError("Niezgodna sygnatura przedłużenia. Przerwano bez zmian.")
    body = body.replace(signature, signature +
                        "    expected_end: datetime | None = None,\n", 1)
    marker = '        end = link.get("valid_until")\n'
    if body.count(marker) != 1:
        raise RuntimeError("Niezgodna obsługa terminu helpera. Przerwano bez zmian.")
    body = body.replace(marker, marker +
                        '        if expected_end is not None and end != expected_end:\n'
                        '            raise HTTPException(409, "Termin zmienił się. Odśwież stronę.")\n', 1)
    if not all(x in body for x in
        ("WHERE " , " FOR UPDATE", "guard.license_extensions",
         "_keygate_set_valid_until(", "if earlier:", "_add_months(end, months)")):
        raise RuntimeError("Brak idempotencji / KeyGate absolutnej daty.")
    return insert_function(src, "_extend_active_license", body), True

def patched(original: str):
    before = names(original)
    if NEW_GET in before or NEW_POST in before or URL in original:
        raise RuntimeError("Ekran płatnych przedłużeń już zainstalowany lub istnieje kolizja tras.")
    if not all(name in before for name in
               ("_extend_active_license", "_workshop_csrf",
                "_owner_effective_entitlement_mode", "panel_licenses_grid",
                "panel_grid_save_row")):
        raise RuntimeError("Oczekiwana instalacja V4.4 nie jest kompletna.")
    if ("STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET."
            not in original):
        raise RuntimeError("Brakuje blokady przełączania trybu serwisowego.")
    updated, engine_modified = update_extension_engine(original)
    updated = updated.rstrip() + "\n\n" + ROUTES.strip() + "\n"
    compile(updated, str(LICENSE), "exec")
    after = names(updated)
    if set(after) - set(before) != {NEW_GET, NEW_POST}:
        raise RuntimeError("Nieoczekiwane nowe funkcje aplikacji.")
    if set(before) - set(after):
        raise RuntimeError("Usunięto istniejącą funkcję V4.4.")
    for name in before:
        if name == "_extend_active_license" and engine_modified:
            continue
        if ast.dump(before[name], include_attributes=False) != ast.dump(
            after[name], include_attributes=False):
            raise RuntimeError("Zmodyfikowano chronioną funkcję V4.4: " + name)
    for route in (URL, URL + "/{link_id}/extend"):
        if updated.count('@router.get("'+route+'"') + updated.count('@router.post("'+route+'"') != 1:
            raise RuntimeError("Brak unikatowej trasy "+route)
    return updated, engine_modified

def protected_status():
    req=urllib.request.Request(
        "https://api.multi-servis.pl/multiguard/panel/licenses-grid",
        headers={"Cache-Control":"no-cache"},
    )
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code

def renewal_status():
    req=urllib.request.Request(
        "https://api.multi-servis.pl"+URL,
        headers={"Cache-Control":"no-cache"},
    )
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code

def ensure_no_open_sessions():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as con:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            exists=con.execute(text("SELECT to_regclass(:table_name)"),
                              {"table_name":table}).scalar_one_or_none()
            if exists is None:
                continue
            opened=con.execute(text(
                "SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
            )).scalar_one()
            if opened:
                raise RuntimeError("Są aktywne sesje zdalne. Bez restartu: "+table)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    current=LICENSE.read_text()
    updated, engine_modified=patched(current)
    baseline=protected_status()
    if baseline not in (401,403):
        raise RuntimeError("Panel OWNER nie wymaga oczekiwanego uwierzytelnienia.")
    print("V4.4 TABLE/CSS: NOT MODIFIED")
    print("PAID CLIENT LICENCES: ACTIVE ONLY, ALL SALE KINDS")
    print("EXTENSIONS: +3/+6/+12 MONTHS FROM ORIGINAL END")
    print("OWNER AUTH / CSRF / PAYMENT / IDEMPOTENCY: GUARDED")
    print("OLD SERVICE MODE FLAGS: UNCHANGED")
    print("EXPECTED END STALE-WRITE GUARD: "+"ADDED" if engine_modified else "EXPECTED END STALE-WRITE GUARD: PRESENT")
    if not args.apply:
        print("OWNER PAID RENEWALS: PREFLIGHT PASS (NO CHANGES)")
        return
    ensure_no_open_sessions()
    backup=ROOT/("backup-mg-paid-renewals-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700, exist_ok=False)
    shutil.copy2(LICENSE,backup/LICENSE.name)
    written=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-paid-renewals-",dir=ROUTERS)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as out:
                out.write(updated)
            os.chmod(tmp,0o644)
            os.replace(tmp,LICENSE)
            written=True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],
                       check=True,timeout=45)
        for _ in range(15):
            active=subprocess.run(["systemctl","is-active","--quiet","multiservis-api.service"],
                                   timeout=8).returncode==0
            if (active and protected_status()==baseline
                    and renewal_status() in (401,403)):
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI lub uwierzytelnienie OWNER nie przeszło weryfikacji.")
        print("OWNER PAID RENEWALS: APPLIED")
        print("NOWY EKRAN:", "https://api.multi-servis.pl"+URL)
        print("LICENCE RECORDS / KEYGATE / MESH: UNCHANGED UNTIL OWNER CONFIRMS RENEWAL")
        print("BACKUP:",backup)
    except Exception:
        if written:
            shutil.copy2(backup/LICENSE.name,LICENSE)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
