"""Owner-only editable notes and priorities attached to a physical Multi-Guard installation.

No change to the Windows agent, KeyGate licences or client-submitted telemetry.
"""
from __future__ import annotations

import html
import json
import threading
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.database import engine
from app.routers.multiguard_license import _panel_auth
from app.routers.multiguard_panel_settings import _csrf_token, _token_valid
import time

router = APIRouter(tags=["multiguard-owner-device-notes"])
_LOCK = threading.Lock()
_READY = False

_PRIORITY = {
    "NORMAL": ("Standardowy", "mg-blue"),
    "WATCH": ("Obserwuj", "mg-gold"),
    "URGENT": ("Pilne", "mg-red"),
}


def _schema() -> None:
    global _READY
    if _READY:
        return
    with _LOCK:
        if _READY:
            return
        with engine.begin() as con:
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_device_notes (
                    installation_id UUID PRIMARY KEY
                        REFERENCES guard.installations(id) ON DELETE CASCADE,
                    priority TEXT NOT NULL DEFAULT 'NORMAL'
                        CHECK (priority IN ('NORMAL','WATCH','URGENT')),
                    note TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_device_notes_audit (
                    id BIGSERIAL PRIMARY KEY,
                    installation_id UUID NOT NULL,
                    before_state JSONB NOT NULL,
                    after_state JSONB NOT NULL,
                    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
        _READY = True


def owner_device_note(installation_id: uuid.UUID) -> dict[str, str]:
    _schema()
    with engine.connect() as con:
        row = con.execute(text("""
            SELECT priority,note FROM guard.owner_device_notes
            WHERE installation_id=:id
        """), {"id":installation_id}).mappings().first()
    return dict(row) if row else {"priority":"NORMAL","note":""}


def owner_device_note_form(installation_id: uuid.UUID, data: dict[str,str]) -> str:
    token = _csrf_token(int(time.time() // 3600))
    choices = "".join(
        f'<option value="{name}" {"selected" if data["priority"]==name else ""}>'
        f'{html.escape(label)}</option>'
        for name,(label,_) in _PRIORITY.items()
    )
    note = html.escape(data.get("note",""),quote=True)
    return f"""
      <section class="card" id="owner-notes">
        <div class="eyebrow">PANEL WŁAŚCICIELA / NOTATKI WEWNĘTRZNE</div>
        <h2>Ocena i uwagi do urządzenia</h2>
        <p>Możesz oznaczyć komputer do obserwacji i uzupełnić własne uwagi.
        Informacji tych nie przesyłamy na komputer klienta; nie zastępują
        historii napraw, raportów z czujników ani licencji.</p>
        <form method="post" action="/multiguard/panel/device/{installation_id}/note">
          <input type="hidden" name="csrf_token" value="{token}">
          <label>Priorytet obserwacji<select name="priority">{choices}</select></label>
          <label>Notatka serwisowa<textarea name="note" maxlength="4000" rows="5"
          placeholder="Np. sporadyczne restarty przy pracy na baterii; sprawdzić WHEA.">{note}</textarea></label>
          <button type="submit">ZAPISZ NOTATKĘ</button>
        </form>
      </section>"""


@router.post("/multiguard/panel/device/{installation_id}/note")
def save_owner_device_note(
    installation_id: uuid.UUID,
    priority: str = Form(...),
    note: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Wygasły lub nieprawidłowy formularz.")
    if priority not in _PRIORITY or len(note) > 4000:
        raise HTTPException(400,"Nieprawidłowy priorytet lub zbyt długa notatka.")
    _schema()
    with engine.begin() as con:
        installed=con.execute(text("""
            SELECT id FROM guard.installations
            WHERE id=:id AND is_current=TRUE LIMIT 1
        """),{"id":installation_id}).first()
        if not installed:
            raise HTTPException(404,"Nie znaleziono bieżącej instalacji.")
        before=con.execute(text("""
            SELECT priority,note FROM guard.owner_device_notes
            WHERE installation_id=:id
        """),{"id":installation_id}).mappings().first()
        old=dict(before) if before else {"priority":"NORMAL","note":""}
        changed={"priority":priority,"note":note.strip()}
        if old!=changed:
            con.execute(text("""
                INSERT INTO guard.owner_device_notes(installation_id,priority,note)
                VALUES(:id,:priority,:note)
                ON CONFLICT(installation_id) DO UPDATE
                  SET priority=EXCLUDED.priority,note=EXCLUDED.note,updated_at=now()
            """),{"id":installation_id,**changed})
            con.execute(text("""
                INSERT INTO guard.owner_device_notes_audit(
                    installation_id,before_state,after_state)
                VALUES(:id,CAST(:old AS jsonb),CAST(:new AS jsonb))
            """),{"id":installation_id,"old":json.dumps(old),"new":json.dumps(changed)})
    return RedirectResponse(f"/multiguard/panel/device/{installation_id}#owner-notes",status_code=303)
