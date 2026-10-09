"""Owner-editable panel presentation settings, separate from the Multi-Guard client.

Only OWNER (HTTP Basic, existing shared panel credentials) can change settings.
No settings here change licences, signed manifests, service reports or client polling.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import threading
import time

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text

from app.database import engine
from app.routers.multiguard_license import _panel_auth, _panel_html

router = APIRouter(tags=["multiguard-owner-panel-settings"])

_SETTINGS = {
    "contact_recent_hours": (24, 1, 72, "Zielona kropka: kontakt w ciągu (godzin)"),
    "contact_delayed_days": (7, 2, 30, "Żółta kropka: brak kontaktu do (dni)"),
    "no_contact_filter_days": (7, 1, 90, "Filtr brak kontaktu: co najmniej (dni)"),
    "inventory_page_size": (50, 20, 100, "Komputerów na stronie"),
}
_LOCK = threading.Lock()
_READY = False


def _schema() -> None:
    global _READY
    if _READY:
        return
    with _LOCK:
        if _READY:
            return
        with engine.begin() as db:
            db.execute(text("""
                CREATE SCHEMA IF NOT EXISTS guard
            """))
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_panel_settings (
                    key TEXT PRIMARY KEY,
                    int_value INTEGER NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.owner_panel_settings_audit (
                    id BIGSERIAL PRIMARY KEY,
                    settings_before JSONB NOT NULL,
                    settings_after JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
        _READY = True


def owner_panel_config() -> dict[str, int]:
    _schema()
    result = {name: spec[0] for name, spec in _SETTINGS.items()}
    with engine.connect() as db:
        rows = db.execute(text("""
            SELECT key,int_value FROM guard.owner_panel_settings
            WHERE key IN ('contact_recent_hours','contact_delayed_days',
                          'no_contact_filter_days','inventory_page_size')
        """)).mappings()
        for item in rows:
            name = item["key"]
            minimum, maximum = _SETTINGS[name][1:3]
            value = item["int_value"]
            if isinstance(value, int) and minimum <= value <= maximum:
                result[name] = value
    return result


def _csrf_token(period: int) -> str:
    # HTTP Basic is sent automatically by browsers. Require an unguessable
    # same-origin form token so cross-origin pages cannot alter owner settings.
    password = os.environ.get("MULTIGUARD_PANEL_PASSWORD", "")
    if not password:
        raise HTTPException(503, "Brak bezpiecznej konfiguracji uwierzytelniania panelu.")
    return hmac.new(
        password.encode("utf-8"),
        f"multi-guard-owner-panel-config:v1:{period}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _token_valid(token: str) -> bool:
    current = int(time.time() // 3600)
    return any(hmac.compare_digest(token, _csrf_token(p)) for p in (current, current - 1))


@router.get("/multiguard/panel/settings", response_class=HTMLResponse)
def panel_settings(saved: int = 0, _: None = Depends(_panel_auth)):
    config = owner_panel_config()
    fields = "".join(
        f'<label>{html.escape(spec[3])}'
        f'<input type="number" name="{name}" min="{spec[1]}" max="{spec[2]}" '
        f'required value="{config[name]}"></label>'
        for name, spec in _SETTINGS.items()
    )
    notice = '<p class="ok">Ustawienia panelu zostały zapisane.</p>' if saved == 1 else ""
    return HTMLResponse(
        _panel_html(f"""
          <section class="card panel-hero">
            <div class="eyebrow">MULTI-SERVIS / KONFIGURACJA WŁAŚCICIELA</div>
            <h1>Ustawienia panelu</h1>
            <p>Progi łączności i wielkość listy można zmieniać bez przebudowy aplikacji.
            Nie modyfikuje to działania Multi-Guard na komputerach klientów.</p>
          </section>
          <section class="card">
            <h2>Komputery i ostatni kontakt</h2>
            {notice}
            <form method="post" action="/multiguard/panel/settings">
              <input type="hidden" name="csrf_token" value="{_csrf_token(int(time.time() // 3600))}">
              <div class="detail-facts">{fields}</div>
              <p class="muted">Zielona kropka: czas ostatniego raportu, nie „komputer online”.
              Po komunikacie odinstalowania komputer trafia do archiwalnego filtra.</p>
              <button type="submit">ZAPISZ USTAWIENIA</button>
            </form>
          </section>
          <section class="card">
            <h2>Parametry diagnostyki — następny etap</h2>
            <p>Profil SERWISOWA / DIAGNOSTYCZNA (Standard lub Pro) wymaga osobnego
            wdrożenia w programie Windows i na serwerze licencji. Uzgodnione
            wartości wyjściowe: próbki co 5–10 s, pakiet co 60 s,
            szczegółowy raport co 5 min i pilne alerty od razu.</p>
            <p>Nie pokazujemy tu pozornej możliwości zmiany częstotliwości,
            dopóki agent rzeczywiście nie pobiera tych ustawień.</p>
          </section>
        """),
        headers={"Cache-Control":"no-store", "X-Frame-Options":"DENY"},
    )


@router.post("/multiguard/panel/settings")
def save_panel_settings(
    contact_recent_hours: int = Form(...),
    contact_delayed_days: int = Form(...),
    no_contact_filter_days: int = Form(...),
    inventory_page_size: int = Form(...),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły lub nieprawidłowy formularz. Odśwież ustawienia.")
    values = {
        "contact_recent_hours": contact_recent_hours,
        "contact_delayed_days": contact_delayed_days,
        "no_contact_filter_days": no_contact_filter_days,
        "inventory_page_size": inventory_page_size,
    }
    for name, value in values.items():
        minimum, maximum = _SETTINGS[name][1:3]
        if not (minimum <= value <= maximum):
            raise HTTPException(400, f"Parametr {name} poza dozwolonym zakresem.")
    if contact_recent_hours >= contact_delayed_days * 24:
        raise HTTPException(400, "Próg zielony musi być krótszy od żółtego.")
    before = owner_panel_config()
    _schema()
    with engine.begin() as db:
        for name, value in values.items():
            db.execute(text("""
                INSERT INTO guard.owner_panel_settings(key,int_value)
                VALUES(:key,:value)
                ON CONFLICT(key) DO UPDATE SET
                    int_value=EXCLUDED.int_value,updated_at=now()
            """), {"key":name, "value":value})
        db.execute(text("""
            INSERT INTO guard.owner_panel_settings_audit(settings_before,settings_after)
            VALUES(CAST(:old AS jsonb),CAST(:new AS jsonb))
        """), {"old":json.dumps(before), "new":json.dumps(values)})
    return RedirectResponse("/multiguard/panel/settings?saved=1",status_code=303)
