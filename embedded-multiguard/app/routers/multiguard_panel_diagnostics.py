"""Owner-only diagnostic licence preparation, no customer activation.

This module NEVER issues a KeyGate licence, never changes a commercial licence
and never signs client entitlements. Agent-side Standard/Pro diagnostic support
will be added in a separately tested Multi-Guard BETA milestone.
"""
from __future__ import annotations

import html
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from app.database import engine
from app.routers.multiguard_license import _panel_auth
from app.routers.multiguard_panel_settings import _csrf_token, _token_valid
import time

router=APIRouter(tags=["multiguard-owner-diagnostics"])
_LOCK=threading.Lock()
_READY=False
_DAYS=(1,2,3,7,14,30,60,90)


def _schema():
    global _READY
    if _READY: return
    from app.routers import multiguard_runtime
    multiguard_runtime._ensure_schema()
    with _LOCK:
        if _READY: return
        with engine.begin() as db:
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_diagnostic_plans (
                  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                  installation_id UUID NOT NULL
                      REFERENCES guard.installations(id) ON DELETE CASCADE,
                  service_device_id UUID NOT NULL
                      REFERENCES core.devices(id) ON DELETE RESTRICT,
                  edition TEXT NOT NULL CHECK(edition IN ('STANDARD','PRO')),
                  status TEXT NOT NULL DEFAULT 'PREPARED'
                      CHECK(status IN ('PREPARED','CANCELLED','ISSUED')),
                  planned_until TIMESTAMPTZ NOT NULL,
                  owner_note TEXT NOT NULL DEFAULT '',
                  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            db.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_guard_owner_diag_prepared
                ON guard.owner_diagnostic_plans(installation_id)
                WHERE status='PREPARED'
            """))
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_diagnostic_plans_audit (
                  id BIGSERIAL PRIMARY KEY,
                  diagnostic_plan_id UUID NOT NULL,
                  installation_id UUID NOT NULL,
                  action TEXT NOT NULL,
                  before_state JSONB NOT NULL,
                  after_state JSONB NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
        _READY=True


def _h(x: object) -> str:
    return html.escape(str(x if x is not None else ""),quote=True)


def _dt(x: datetime|None) -> str:
    return x.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC") if x else "—"


def owner_diagnostic_plan_panel(installation_id:uuid.UUID) -> str:
    _schema()
    with engine.connect() as db:
        row=db.execute(text("""
            SELECT id,edition,planned_until,owner_note,created_at
            FROM guard.owner_diagnostic_plans
            WHERE installation_id=:iid AND status='PREPARED'
            ORDER BY created_at DESC LIMIT 1
        """),{"iid":installation_id}).mappings().first()
        historic=db.execute(text("""
            SELECT id,edition,status,planned_until,created_at
            FROM guard.owner_diagnostic_plans
            WHERE installation_id=:iid
            ORDER BY created_at DESC LIMIT 20
        """),{"iid":installation_id}).mappings().all()
    plan_text=(
        f'<div class="detail-facts"><div class="detail-fact"><b>Przygotowany plan</b>'
        f'<span>Serwis {_h(row["edition"])} · do {_dt(row["planned_until"])}</span></div></div>'
        if row else '<p class="muted">Nie przygotowano jeszcze planu diagnostyki.</p>'
    )
    action='extend' if row else 'prepare'
    action_label='PRZEDŁUŻ PRZYGOTOWANY PLAN' if row else 'PRZYGOTUJ PLAN'
    cancel_button=(
        f'<form method="post" action="/multiguard/panel/device/{installation_id}/diagnostic-plan">'
        f'<input name="csrf_token" type="hidden" value="{_csrf_token(int(time.time()//3600))}">'
        f'<input name="action" type="hidden" value="cancel">'
        f'<button type="submit" class="button-link">ANULUJ PLAN</button></form>'
        if row else ''
    )
    editions="".join(
        f'<option value="{kind}" {"selected" if row and row["edition"]==kind else ""}>'
        f'{kind}</option>' for kind in ('STANDARD','PRO')
    )
    days="".join(f'<option value="{d}" {"selected" if d==14 else ""}>{d} dni</option>'
                 for d in _DAYS)
    history="".join(
        f'<tr><td>{_dt(item["created_at"])}</td>'
        f'<td>Serwis {_h(item["edition"])}</td><td>{_h(item["status"])}</td>'
        f'<td>{_dt(item["planned_until"])}</td></tr>'
        for item in historic
    ) or '<tr><td colspan="4">Nie było wcześniejszych planów.</td></tr>'
    return f"""
    <section class="card" id="diagnostic-plan">
      <div class="eyebrow">MULTI-SERVIS / PRZYGOTOWANIE DIAGNOSTYKI</div>
      <h2>Serwisowa licencja diagnostyczna — Standard / Pro</h2>
      <p><span class="badge mg-gold">TYLKO PRZYGOTOWANIE · NIEAKTYWNA</span>
      Tutaj przygotowujemy przyszłe uprawnienie i jego okres. Program Windows
      nie obsługuje jeszcze diagnostycznych licencji, dlatego zapis planu
      <strong>nie włącza monitorowania ani funkcji Multi-Guard</strong>.
      Nie zmieniamy istniejącej licencji klienta i nie używamy KeyGate.</p>
      {plan_text}
      <form method="post" action="/multiguard/panel/device/{installation_id}/diagnostic-plan">
        <input name="csrf_token" type="hidden" value="{_csrf_token(int(time.time()//3600))}">
        <input name="action" type="hidden" value="{action}">
        <div class="detail-facts">
          <label>Zakres edycji<select name="edition">{editions}</select></label>
          <label>Okres planowania<select name="days">{days}</select></label>
        </div>
        <label>Uwagi OWNER (np. objawy i oczekiwane dane)
          <textarea name="owner_note" maxlength="2000" rows="3">{_h(row["owner_note"] if row else "")}</textarea>
        </label>
        <button type="submit">{action_label}</button>
      </form>
      {cancel_button}
      <h3>Historia przygotowań</h3>
      <div class="table-wrap"><table><thead><tr><th>Utworzono</th><th>Edycja</th>
      <th>Stan</th><th>Do</th></tr></thead><tbody>{history}</tbody></table></div>
    </section>
    """


@router.post("/multiguard/panel/device/{installation_id}/diagnostic-plan")
def save_owner_diagnostic_plan(
    installation_id:uuid.UUID,
    action:str=Form(...),
    edition:str=Form("STANDARD"),
    days:int=Form(14),
    owner_note:str=Form(""),
    csrf_token:str=Form(...),
    _:None=Depends(_panel_auth),
):
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Nieprawidłowy lub wygasły formularz.")
    if action not in ("prepare","extend","cancel") or edition not in ("STANDARD","PRO") or days not in _DAYS or len(owner_note)>2000:
        raise HTTPException(400,"Nieprawidłowe parametry planu.")
    _schema()
    with engine.begin() as db:
        installation=db.execute(text("""
            SELECT id,service_device_id FROM guard.installations
            WHERE id=:id AND is_current=TRUE LIMIT 1
        """),{"id":installation_id}).mappings().first()
        if installation is None: raise HTTPException(404,"Nie znaleziono komputera.")
        current=db.execute(text("""
            SELECT id,edition,status,planned_until,owner_note
            FROM guard.owner_diagnostic_plans
            WHERE installation_id=:id AND status='PREPARED' FOR UPDATE
        """),{"id":installation_id}).mappings().first()
        before=(
            {k:(v.isoformat() if isinstance(v,datetime) else str(v) if isinstance(v,uuid.UUID) else v)
             for k,v in dict(current).items()}
            if current else {}
        )
        if action=="prepare":
            if current: raise HTTPException(409,"Plan już istnieje. Wybierz przedłużenie.")
            # Future activation will start counting ONLY after client acceptance,
            # not when preparing the plan.
            planned_until=datetime.now(timezone.utc)+timedelta(days=days)
            row=db.execute(text("""
                INSERT INTO guard.owner_diagnostic_plans(
                    installation_id,service_device_id,edition,planned_until,owner_note)
                VALUES(:iid,:did,:edition,:until,:note)
                RETURNING id
            """),{"iid":installation_id,"did":installation["service_device_id"],
                  "edition":edition,"until":planned_until,"note":owner_note.strip()}).mappings().one()
            plan_id=row["id"]
        elif action=="extend":
            if current is None: raise HTTPException(409,"Brak planu do przedłużenia.")
            planned_until=max(current["planned_until"],datetime.now(timezone.utc))+timedelta(days=days)
            plan_id=current["id"]
            db.execute(text("""
                UPDATE guard.owner_diagnostic_plans
                SET edition=:edition,planned_until=:until,owner_note=:note,updated_at=now()
                WHERE id=:id
            """),{"id":plan_id,"edition":edition,"until":planned_until,"note":owner_note.strip()})
        else:
            if current is None: raise HTTPException(409,"Nie ma aktywnego planu do anulowania.")
            plan_id=current["id"]
            db.execute(text("""
                UPDATE guard.owner_diagnostic_plans
                SET status='CANCELLED',updated_at=now() WHERE id=:id
            """),{"id":plan_id})
        after={
            "edition":edition if action!="cancel" else before["edition"],
            "status":"CANCELLED" if action=="cancel" else "PREPARED",
            "planned_until":planned_until.isoformat() if action!="cancel" else before["planned_until"],
            "owner_note":owner_note.strip() if action!="cancel" else before["owner_note"],
        }
        db.execute(text("""
            INSERT INTO guard.owner_diagnostic_plans_audit(
                diagnostic_plan_id,installation_id,action,before_state,after_state)
            VALUES(:pid,:iid,:action,CAST(:before AS jsonb),CAST(:after AS jsonb))
        """),{"pid":plan_id,"iid":installation_id,"action":action,
              "before":json.dumps(before),"after":json.dumps(after)})
    return RedirectResponse(
        f"/multiguard/panel/device/{installation_id}#diagnostic-plan",status_code=303
    )
