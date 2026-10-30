#!/usr/bin/env python3
"""Surgical OWNER V4.4 grid controls: Pro / Standard / Service + calendar.

NO change to the existing table route, layout, styling or KeyGate calls:
inject one local HTMLResponse adapter into the production grid renderer,
and add pure HTML transformation helpers. Existing Save receives the new
term_choice, term_date and payment_confirmed fields. Service transitions
remain hard-locked until Windows/Mesh consent checks are complete.

One-file atomic deployment, backup, rollback, idempotency and preflight.
Never changes licence records. No staged FastAPI module replaces production.
"""
from __future__ import annotations
import argparse
import ast
import copy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path("/opt/multiservis")
SOURCE=ROOT/"app/routers/multiguard_license.py"
NAME="panel_licenses_grid"
HELPER="_mg_v44_grid_response"
URL="https://api.multi-servis.pl/multiguard/panel/licenses-grid"

HELPERS=r'''
def _mg_v44_grid_response(content, *args, **kwargs):
    """Adapt only the OWNER grid HTML, keeping all normal response arguments."""
    from fastapi.responses import HTMLResponse as _HTMLResponse
    return _HTMLResponse(_mg_v44_grid_transform(str(content)), *args, **kwargs)


def _mg_v44_grid_transform(doc: str) -> str:
    """Render the specified three editions and independent expiry picker."""
    import re
    from html import escape as esc

    if 'data-mg-v44-term-version="1"' in doc:
        return doc
    form_action = re.compile(
        r"""<form\b[^>]*action=["'][^"']*/multiguard/panel/licenses-grid/"""
        r"""[^"']+/save["'][^>]*>""",re.I|re.S)
    # Grid headers, not an incidental action link or another detail table.
    header = re.search(r'<thead\b[^>]*>(.*?)</thead\s*>',doc,re.I|re.S)
    if not header:
        raise RuntimeError("Brak nagłówka tabeli V4.4")
    headings = [re.sub(r'<[^>]*>', '', h).strip().lower()
                for h in re.findall(r'<th\b[^>]*>(.*?)</th\s*>',
                                    header.group(1),re.I|re.S)]
    expiry_index = next((i for i,h in enumerate(headings)
                         if any(key in h for key in ("ważn", "termin", "wygas", "data końc"))),None)
    if expiry_index is None:
        raise RuntimeError("Nie rozpoznano kolumny Ważna do V4.4")

    selection = re.compile(
        r"""(?P<open><select\b(?=[^>]*\bname=["']target_edition["'])[^>]*>)"""
        r'(?P<items>.*?)</select\s*>',re.I|re.S)
    term_select = re.compile(
        r"""(?P<open><select\b(?=[^>]*\bname=["']term_choice["'])[^>]*>)"""
        r'(?P<items>.*?)</select\s*>',re.I|re.S)

    def attr(tag,attribute):
        hit = re.search(r'\b'+re.escape(attribute)+r"""\s*=\s*(["'])(.*?)\1""",
                        tag,re.I|re.S)
        return hit.group(2) if hit else None

    def edition(menu):
        selected = "STANDARD"
        for item in re.findall(r'<option\b[^>]*>',menu.group("items"),re.I|re.S):
            if re.search(r'\bselected(?:\s*=|\s|>)',item,re.I):
                selected=attr(item,"value") or selected
                break
        selected=selected.upper()
        if selected not in ("PRO","STANDARD","SERVICE"):
            selected="STANDARD"
        choices="".join('<option value="'+value+'"'+(' selected' if value==selected else '')+'>'+label+'</option>'
                       for value,label in (("PRO","Pro"),("STANDARD","Standard"),("SERVICE","Service")))
        opening=menu.group("open")
        if "data-mg-original-edition" not in opening:
            opening=opening[:-1]+' data-mg-original-edition="'+selected+'">'
        return opening+choices+"</select>"

    def terms(opening):
        options = (
            '<option value="KEEP" selected>Bez zmian</option>'
            '<option value="3">3 miesiące</option>'
            '<option value="6">6 miesięcy</option>'
            '<option value="12">12 miesięcy</option>'
            '<option value="CALENDAR">Wybierz datę…</option>'
            '<option value="PERPETUAL">Bezterminowa (Service)</option>'
        )
        return opening+options+"</select>"

    rows_re=re.compile(r'<tr\b[^>]*>.*?</tr\s*>',re.I|re.S)
    patched_count=[0]
    def patch_row(match):
        row=match.group(0)
        form=form_action.search(row)
        if not form:
            return row
        sel=selection.search(row)
        if not sel:
            raise RuntimeError("Wiersz V4.4 nie ma pola edycji")
        form_id=attr(form.group(0),"id")
        if not form_id:
            form_id=attr(sel.group("open"),"form")
        if not form_id or not re.fullmatch(r'[a-zA-Z0-9_-]{2,110}',form_id):
            raise RuntimeError("Brak poprawnego identyfikatora formularza V4.4")
        cells=list(re.finditer(r'<td\b[^>]*>.*?</td\s*>',row,re.I|re.S))
        if expiry_index>=len(cells):
            raise RuntimeError("Brak kolumny ważności w wierszu V4.4")

        updated=selection.sub(edition,row,count=1)
        expiry_cell=cells[expiry_index].group(0)
        existing=term_select.search(expiry_cell)
        if existing:
            expiry_cell=term_select.sub(lambda m:terms(m.group("open")),expiry_cell,count=1)
        else:
            # Place the control in the EXISTING expiry column, not a new page.
            form_ref=esc(form_id,quote=True)
            expiry_cell=expiry_cell.replace("</td>",
                '<details class="mg-grid-term-picker" data-mg-v44-term-version="1">'
                '<summary>Wybierz ważność ▾</summary>'
                '<div class="mg-grid-term-menu">'
                +terms('<select class="mg-grid-term-choice" name="term_choice" form="'+form_ref+'">')
                +'</div></details></td>',1)

        # Ensure a real native HTML date picker is bound to the same Save.
        if not re.search(r"""<input\b(?=[^>]*\bname=["']term_date["'])""",expiry_cell,re.I|re.S):
            form_ref=esc(form_id,quote=True)
            expiry_cell=expiry_cell.replace("</td>",
                '<input type="date" name="term_date" form="'+form_ref+'" '
                'aria-label="Data ważności licencji" hidden>'
                '</td>',1)
        if not re.search(r"""<input\b(?=[^>]*\bname=["']payment_confirmed["'])""",expiry_cell,re.I|re.S):
            expiry_cell=expiry_cell.replace("</td>",
                '<label class="mg-v44-paid-confirm" hidden>'
                '<input type="checkbox" name="payment_confirmed" form="'+esc(form_id,quote=True)+'" value="yes">'
                'Potwierdzam otrzymanie płatności</label>'
                '</td>',1)

        current_cells=list(re.finditer(r'<td\b[^>]*>.*?</td\s*>',updated,re.I|re.S))
        target=current_cells[expiry_index]
        updated=updated[:target.start()]+expiry_cell+updated[target.end():]
        if 'data-mg-v44-term-version="1"' not in updated:
            updated=updated.replace("<tr",'<tr data-mg-v44-term-version="1"',1)
        # Normalize the edition naming, but only inside the relevant row.
        updated=updated.replace(">Serwisowa</option>",">Service</option>")
        patched_count[0]+=1
        return updated

    transformed=rows_re.sub(patch_row,doc)
    if not patched_count[0]:
        raise RuntimeError("Brak formularzy Save w tabeli V4.4 — odmowa zmian")

    # Do not replace or remove the page's existing scripts. Add one small
    # enhancement for showing the date picker, validation and Save activation.
    js = r"""
<script data-mg-v44-term-version="1">
(function(){
  "use strict";
  document.querySelectorAll('tr[data-mg-v44-term-version="1"]').forEach(function(row){
    var edition=row.querySelector('select[name="target_edition"]');
    var term=row.querySelector('select[name="term_choice"]');
    if(!edition||!term)return;
    var id=edition.getAttribute('form')||term.getAttribute('form');
    if(!id)return;
    var date=row.querySelector('input[name="term_date"][form="'+id+'"]');
    var payment=row.querySelector('input[name="payment_confirmed"][form="'+id+'"]');
    var save=document.querySelector('button.grid-save[form="'+id+'"]')
          ||row.querySelector('button[type="submit"][form="'+id+'"]');
    var form=document.getElementById(id);
    if(!date||!form)return;
    var original=(edition.dataset.mgOriginalEdition||edition.value).toUpperCase();
    function update(){
      var choice=term.value, isDate=choice==="CALENDAR";
      date.hidden=!isDate;
      date.required=isDate;
      if(!isDate)date.value="";
      var isPaid=edition.value!=="SERVICE";
      var needsPayment=isPaid&&(choice==="3"||choice==="6"||choice==="12");
      if(payment){
        var label=payment.closest('label');
        if(label)label.hidden=!needsPayment;
        payment.required=needsPayment;
        if(!needsPayment)payment.checked=false;
      }
      var changed=edition.value!==original || choice!=="KEEP";
      if(save && changed)save.disabled=Boolean(isDate&&!date.value);
      if(save && !changed){
        // Leave legacy V4.4 name/channel Save control unchanged.
        save.dispatchEvent(new Event('mg-v44-update',{bubbles:false}));
      }
    }
    edition.addEventListener('change',update);
    term.addEventListener('change',update);
    date.addEventListener('change',update);
    date.addEventListener('input',update);
    form.addEventListener('submit',function(e){
      if(term.value==="CALENDAR"&&!date.value){
        e.preventDefault();
        date.hidden=false;
        date.focus();
      }
      if(edition.value==="SERVICE"&&term.value==="KEEP"&&original!=="SERVICE"){
        e.preventDefault();
        alert("Wybierz okres dla licencji Service.");
      }
    });
    update();
  });
})();
</script>
"""
    # html document generated by normal V4.4 _panel_html()
    if re.search(r'</body\s*>',transformed,re.I):
        transformed=re.sub(r'</body\s*>',lambda m:js+m.group(0),transformed,count=1,flags=re.I)
    else:
        transformed+=js
    return transformed


'''
# script below is deployed as runtime adaptation but not a standalone replacement
def parse(src):
    tree=ast.parse(src)
    return {n.name:n for n in tree.body
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def add_adapter(src: str):
    found=parse(src)
    if HELPER in found:
        raise RuntimeError("Nakładka interfejsu jest już wdrożona; brak zmian.")
    if NAME not in found or "panel_grid_save_row" not in found:
        raise RuntimeError("Produkcja nie ma oczekiwanych funkcji V4.4")
    if "_owner_v44_grid_term_selection" not in found:
        raise RuntimeError("Produkcja nie ma aktywnej obsługi zapisu okresów.")
    if 'STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.' not in src:
        raise RuntimeError("Brak ochrony przełączania Service.")
    renderer=found[NAME]
    body=ast.get_source_segment(src,renderer)
    if not body or "HTMLResponse" not in body or 'grid' not in body.lower():
        raise RuntimeError("Nieznana funkcja renderowania V4.4")
    if any(isinstance(n,ast.Name) and n.id=="HTMLResponse" and
           isinstance(n.ctx,ast.Store) for n in ast.walk(renderer)):
        raise RuntimeError("HTMLResponse ma już lokalne przypisanie")
    first=renderer.body[0]
    # Preserve every existing V4.4 statement and layout; intercept only
    # the final HTMLResponse construction within this one route.
    lines=src.splitlines(keepends=True)
    if first.col_offset!=4:
        raise RuntimeError("Nieznane wcięcie funkcji renderowania")
    lines.insert(first.lineno-1,"    HTMLResponse = _mg_v44_grid_response\n")
    result="".join(lines).rstrip()+"\n\n"+HELPERS.strip()+"\n"
    compile(result,str(SOURCE),"exec")
    now=parse(result)
    if set(now)-set(found)!={HELPER,"_mg_v44_grid_transform"}:
        raise RuntimeError("Nieoczekiwane funkcje po zmianie")
    if set(found)-set(now):
        raise RuntimeError("Zniknęła chroniona funkcja V4.4")
    for name in found:
        if name==NAME:
            continue
        if ast.dump(found[name],include_attributes=False)!=ast.dump(now[name],include_attributes=False):
            raise RuntimeError("Zmiana funkcji spoza renderer V4.4: "+name)
    return result

def verify_real_v44_rows():
    """Test HTML generated from the REAL production tables before deployment.

    This is read-only and prints counts, not customer/licence contents.
    No screenshot, expected markup guess or synthetic fixture substitutes it.
    """
    import importlib
    import sys
    sys.path.insert(0,str(ROOT))
    module=importlib.import_module("app.routers.multiguard_license")
    response=module.panel_licenses_grid()
    if response.status_code != 200 or not hasattr(response,"body"):
        raise RuntimeError("Nie można wyrenderować produkcyjnej tabeli V4.4.")
    original=response.body.decode("utf-8")
    pure={}
    exec(compile(HELPERS,"<mg-v44-grid-pure>","exec"),pure)
    result=pure["_mg_v44_grid_transform"](original)
    count=result.count('data-mg-v44-term-version="1"')
    if count < 3 or result.count('value="SERVICE"') == 0:
        raise RuntimeError("Podgląd żywej tabeli nie ma trzech edycji lub kalendarza.")
    if 'name="term_date"' not in result or 'name="term_choice"' not in result:
        raise RuntimeError("Brak kalendarza lub wyboru okresu na żywej tabeli.")
    print("LIVE V4.4 GENERATED HTML: PASS (CUSTOMER DATA NOT PRINTED)")
    print("EXISTING V4.4 SAVE / LIVE GRID ROWS: PRESENT")

def panel_status():
    req=urllib.request.Request(URL,headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code

def no_sessions():
    import sys
    sys.path.insert(0,str(ROOT))
    from sqlalchemy import text
    from app.database import engine
    with engine.connect() as con:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            if con.execute(text("SELECT to_regclass(:name)"),{"name":table}).scalar_one_or_none() is None:
                continue
            count=con.execute(text(
                "SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
            )).scalar_one()
            if count:
                raise RuntimeError("Aktywne sesje zdalne blokują restart: "+table)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    current=SOURCE.read_text()
    newer=add_adapter(current)
    baseline=panel_status()
    if baseline not in (401,403):
        raise RuntimeError("Panel V4.4 nie wymaga oczekiwanego logowania.")
    verify_real_v44_rows()
    print("PRO / STANDARD / SERVICE: PREPARED IN SAME GRID")
    print("3/6/12 / CALENDAR / PERPETUAL: PREPARED")
    print("V4.4 TABLE / NAME / CHANNEL / OLD SAVE: SOURCE UNCHANGED")
    print("SERVICE MODE SWITCH: HARD-LOCKED (WINDOWS/MESH NOT YET VERIFIED)")
    if not args.apply:
        print("GRID V4.4 CONTROLS: PREFLIGHT PASS (NO CHANGES)")
        return
    no_sessions()
    backup=ROOT/("backup-mg-grid-controls-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(SOURCE,backup/SOURCE.name)
    written=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-grid-controls-",dir=SOURCE.parent)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                f.write(newer)
            os.chmod(tmp,0o644)
            os.replace(tmp,SOURCE)
            written=True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],check=True,timeout=45)
        for i in range(18):
            if (subprocess.run(["systemctl","is-active","--quiet","multiservis-api.service"],
                               check=False,timeout=10).returncode==0
                    and panel_status()==baseline):
                break
            time.sleep(1)
        else:
            raise RuntimeError("Weryfikacja FastAPI/V4.4 nie powiodła się")
        print("GRID V4.4 CONTROLS: APPLIED")
        print("TABLE:",URL)
        print("NO KEYGATE / MESH / LICENCE DATA MUTATIONS")
        print("BACKUP:",backup)
    except Exception:
        if written:
            shutil.copy2(backup/SOURCE.name,SOURCE)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
