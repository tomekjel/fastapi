"""Owner-only incident assessment for Multi-Guard events (editable, audited).

Observations from clients remain immutable. Owner assessments have their own
state and audit; do not create an automatic diagnosis from incomplete telemetry.
"""
from __future__ import annotations

import html
import json
import re
import threading
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text

from app.database import engine
from app.routers.multiguard_license import _panel_auth, _panel_html
from app.routers.multiguard_panel_settings import _csrf_token, _token_valid
import time

router=APIRouter(tags=["multiguard-owner-triage"])
_LOCK=threading.Lock()
_READY=False

STATES={
    "NEW":("Nowe","mg-blue"),
    "REVIEWING":("Analizowane","mg-gold"),
    "CONFIRMED":("Potwierdzone","mg-red"),
    "FALSE_ALARM":("Fałszywy alarm","mg-blue"),
    "RESOLVED":("Naprawione","mg-green"),
}


def _schema() -> None:
    global _READY
    if _READY:
        return
    from app.routers import multiguard_runtime
    multiguard_runtime._ensure_schema()
    with _LOCK:
        if _READY:
            return
        with engine.begin() as db:
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_event_triage (
                    event_id UUID PRIMARY KEY REFERENCES guard.events(event_id) ON DELETE CASCADE,
                    state TEXT NOT NULL DEFAULT 'NEW'
                      CHECK(state IN ('NEW','REVIEWING','CONFIRMED','FALSE_ALARM','RESOLVED')),
                    owner_note TEXT NOT NULL DEFAULT '',
                    fixed_in_version TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_event_triage_audit (
                    id BIGSERIAL PRIMARY KEY,
                    event_id UUID NOT NULL,
                    before_state JSONB NOT NULL,
                    after_state JSONB NOT NULL,
                    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
        _READY=True


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""),quote=True)


def _date(value: object) -> str:
    return value.strftime("%d.%m.%Y %H:%M") if isinstance(value, datetime) else "—"


def _read(event_id: uuid.UUID) -> tuple[dict,dict,list[dict]]:
    _schema()
    with engine.connect() as db:
        event=db.execute(text("""
            SELECT e.event_id,e.event_type,e.severity,e.occurred_at,e.received_at,
                   e.payload,e.installation_id,
                   gi.installation_external_id,gi.app_version,
                   d.manufacturer,d.model,d.serial_number
            FROM guard.events e
            JOIN guard.installations gi ON gi.id=e.installation_id
            LEFT JOIN core.devices d ON d.id=gi.service_device_id
            WHERE e.event_id=:id LIMIT 1
        """),{"id":event_id}).mappings().first()
        if event is None:
            raise HTTPException(404,"Nie znaleziono zdarzenia Multi-Guard.")
        current=db.execute(text("""
            SELECT state,owner_note,fixed_in_version,updated_at
            FROM guard.owner_event_triage WHERE event_id=:id
        """),{"id":event_id}).mappings().first()
        history=db.execute(text("""
            SELECT before_state,after_state,changed_at
            FROM guard.owner_event_triage_audit
            WHERE event_id=:id ORDER BY changed_at DESC LIMIT 25
        """),{"id":event_id}).mappings().all()
    return dict(event), (
        dict(current) if current else
        {"state":"NEW","owner_note":"","fixed_in_version":"","updated_at":None}
    ),[dict(x) for x in history]


@router.get("/multiguard/panel/incident/{event_id}", response_class=HTMLResponse)
def incident_owner_detail(
    event_id: uuid.UUID,
    saved: int = 0,
    _: None = Depends(_panel_auth),
):
    event, owner, history=_read(event_id)
    payload=event["payload"] if isinstance(event["payload"],dict) else {}
    summary=next((
        str(payload.get(k)) for k in ("title","summary","message","detail","code")
        if isinstance(payload.get(k),str) and payload.get(k)
    ),"Zapisane zdarzenie agenta Multi-Guard.")[:450]
    hardware=" ".join(
        filter(None,[str(event["manufacturer"] or ""),
                     str(event["model"] or "")])
    ) or "Nieznany komputer"
    options="".join(
        f'<option value="{key}" {"selected" if key==owner["state"] else ""}>{_esc(label)}</option>'
        for key,(label,css) in STATES.items()
    )
    changes="".join(
        f'<tr><td>{_date(item["changed_at"])}</td>'
        f'<td>{_esc(STATES.get(item["before_state"].get("state"),("Nowe",""))[0])}</td>'
        f'<td>{_esc(STATES.get(item["after_state"].get("state"),("Nowe",""))[0])}</td>'
        f'<td>{_esc(item["after_state"].get("fixed_in_version") or "—")}</td></tr>'
        for item in history
    ) or '<tr><td colspan="4">Brak wcześniejszych zmian oceny.</td></tr>'
    label, tone=STATES[owner["state"]]
    saved_note='<p class="ok">Ocena zdarzenia została zapisana.</p>' if saved == 1 else ""
    content=f"""
      <section class="card panel-hero telemetry-hero">
        <div class="eyebrow">MULTI-SERVIS / OCENA ZDARZENIA</div>
        <h1>{_esc(event["event_type"])}</h1>
        <p>{_esc(hardware)} · { _date(event["occurred_at"]) } ·
        Multi-Guard {_esc(event["app_version"] or "—")}</p>
        <div class="detail-facts">
          <div class="detail-fact"><b>Poziom zdarzenia</b><span>{_esc(event["severity"])}</span></div>
          <div class="detail-fact"><b>Ocena właściciela</b><span class="badge {tone}">{_esc(label)}</span></div>
          <div class="detail-fact"><b>Ostatnia zmiana</b><span>{_date(owner["updated_at"])}</span></div>
        </div>
      </section>
      <section class="card">
        <div class="section-head"><div>
          <h2>Co zaobserwował Multi-Guard?</h2>
          <p>{_esc(summary)}</p>
          <p>To zapis zdarzenia, nie automatyczne potwierdzenie przyczyny usterki.</p>
        </div></div>
        <a class="button-link compact" href="/multiguard/panel/device/{event['installation_id']}">
          ← Karta komputera</a>
      </section>
      <section class="card">
        <div class="eyebrow">EDYCJA WŁAŚCICIELA</div>
        <h2>Ocena, weryfikacja i poprawka</h2>
        <p>Zmienia się wyłącznie Twoja ocena. Zgłoszenie od komputera i jego pomiary pozostają nienaruszone.</p>
        {saved_note}
        <form method="post" action="/multiguard/panel/incident/{event_id}">
          <input name="csrf_token" type="hidden" value="{_csrf_token(int(time.time() // 3600))}">
          <label>Stan wyjaśniania zdarzenia<select name="state">{options}</select></label>
          <label>Uwagi i wynik diagnozy<textarea name="owner_note" maxlength="4000" rows="5">{_esc(owner["owner_note"])}</textarea></label>
          <label>Naprawione w wersji (jeżeli sprawdzone)
            <input name="fixed_in_version" maxlength="32"
              value="{_esc(owner["fixed_in_version"])}"
              placeholder="np. 0.3.36"></label>
          <button type="submit">ZAPISZ OCENĘ</button>
        </form>
      </section>
      <section class="card">
        <h2>Historia zmian oceny</h2>
        <div class="table-wrap"><table><thead><tr>
        <th>Data</th><th>Poprzednio</th><th>Nowy stan</th><th>Wersja naprawy</th>
        </tr></thead><tbody>{changes}</tbody></table></div>
      </section>"""
    return HTMLResponse(
        _panel_html(content),
        headers={"Cache-Control":"no-store","X-Frame-Options":"DENY"}
    )


@router.post("/multiguard/panel/incident/{event_id}")
def save_incident_owner_assessment(
    event_id: uuid.UUID,
    state: str = Form(...),
    owner_note: str = Form(""),
    fixed_in_version: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Wygasły lub nieprawidłowy formularz.")
    if state not in STATES or len(owner_note) > 4000 or len(fixed_in_version) > 32:
        raise HTTPException(400,"Nieprawidłowe dane oceny.")
    version=fixed_in_version.strip()
    if version and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?",version):
        raise HTTPException(400,"Wersja naprawy musi mieć postać np. 0.3.36.")
    _schema()
    values={"state":state,"owner_note":owner_note.strip(),"fixed_in_version":version}
    with engine.begin() as db:
        if not db.execute(text("SELECT 1 FROM guard.events WHERE event_id=:id"),{"id":event_id}).first():
            raise HTTPException(404,"Nie znaleziono zdarzenia.")
        row=db.execute(text("""
            SELECT state,owner_note,fixed_in_version
            FROM guard.owner_event_triage WHERE event_id=:id FOR UPDATE
        """),{"id":event_id}).mappings().first()
        before=dict(row) if row else {"state":"NEW","owner_note":"","fixed_in_version":""}
        if values != before:
            db.execute(text("""
                INSERT INTO guard.owner_event_triage(event_id,state,owner_note,fixed_in_version)
                VALUES(:id,:state,:owner_note,:fixed_in_version)
                ON CONFLICT(event_id) DO UPDATE SET
                    state=EXCLUDED.state,owner_note=EXCLUDED.owner_note,
                    fixed_in_version=EXCLUDED.fixed_in_version,updated_at=now()
            """),{"id":event_id,**values})
            db.execute(text("""
                INSERT INTO guard.owner_event_triage_audit(event_id,before_state,after_state)
                VALUES(:id,CAST(:old AS jsonb),CAST(:new AS jsonb))
            """),{"id":event_id,"old":json.dumps(before),"new":json.dumps(values)})
    return RedirectResponse(f"/multiguard/panel/incident/{event_id}?saved=1",status_code=303)
