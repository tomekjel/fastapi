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
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_installation_labels (
                    installation_external_id UUID PRIMARY KEY,
                    friendly_name VARCHAR(120) NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
        _READY = True


def owner_friendly_name(external_id: uuid.UUID) -> str:
    """User-supplied display name, stable across licence edition changes.

    Identified by the Windows installation UUID, not the mutable hostname,
    unreliable serial number or private customer data.
    """
    _schema()
    with engine.connect() as con:
        name = con.execute(text("""
            SELECT friendly_name FROM guard.owner_installation_labels
            WHERE installation_external_id=:id
        """), {"id":external_id}).scalar_one_or_none()
    return str(name or "")


def owner_name_form(external_id: uuid.UUID, value: str, *, return_to: str) -> str:
    """OWNER-only form; never transmitted to a remote Multi-Guard endpoint."""
    token = _csrf_token(int(time.time() // 3600))
    escaped = html.escape(value, quote=True)
    back = html.escape(return_to, quote=True)
    return f"""
      <section class="card" id="owner-name">
        <div class="eyebrow">MULTI-SERVIS / WŁASNA NAZWA</div>
        <h2>Moja nazwa komputera</h2>
        <p>Oryginalny model i nazwa Windows pozostają niezmienione.
           Ta etykieta jest widoczna tylko w panelu właściciela.</p>
        <form method="post" action="/multiguard/panel/installation/{external_id}/name">
          <input type="hidden" name="csrf_token" value="{token}">
          <input type="hidden" name="return_to" value="{back}">
          <label>Nazwa (maks. 120 znaków)
            <input name="friendly_name" maxlength="120" value="{escaped}"
             placeholder="np. ASUS — laptop warsztatowy / Jan Nowak — Bydgoszcz"></label>
          <button type="submit">ZAPISZ NAZWĘ</button>
        </form>
      </section>"""


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


@router.post("/multiguard/panel/installation/{installation_id}/name")
def save_owner_installation_name(
    installation_id: uuid.UUID,
    friendly_name: str = Form(""),
    return_to: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    """Update only OWNER's alias; never overwrite Windows identity/hostname."""
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły lub nieprawidłowy formularz.")
    clean = " ".join(friendly_name.strip().split())
    if len(clean) > 120 or any(ord(ch) < 32 for ch in clean):
        raise HTTPException(400, "Nazwa może mieć maksymalnie 120 znaków.")
    _schema()
    with engine.begin() as con:
        known = con.execute(text("""
            SELECT 1 FROM guard.pending_installations
            WHERE installation_id=:id
            UNION ALL
            SELECT 1 FROM guard.installations
            WHERE installation_external_id=:id
            LIMIT 1
        """), {"id": installation_id}).first()
        if not known:
            raise HTTPException(404, "Nie znaleziono instalacji Multi-Guard.")
        con.execute(text("""
            INSERT INTO guard.owner_installation_labels
                (installation_external_id, friendly_name)
            VALUES (:id, :name)
            ON CONFLICT (installation_external_id) DO UPDATE
              SET friendly_name=EXCLUDED.friendly_name, updated_at=now()
        """), {"id": installation_id, "name": clean})
    # Do not allow an arbitrary external redirect supplied by a form.
    if return_to == "pending":
        target = f"/multiguard/panel/pending/{installation_id}#owner-name"
    elif return_to == "device":
        with engine.connect() as con:
            internal = con.execute(text("""
                SELECT id FROM guard.installations
                WHERE installation_external_id=:id AND is_current=TRUE
                LIMIT 1
            """), {"id": installation_id}).scalar_one_or_none()
        target = (
            f"/multiguard/panel/device/{internal}#owner-name"
            if internal else "/multiguard/panel/computers#pending"
        )
    else:
        target = "/multiguard/panel/computers#pending"
    return RedirectResponse(target, status_code=303)
