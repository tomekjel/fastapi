"""Read-only Multi-Servis service dashboard embedded in the Multi-Guard owner web panel.

Uses the same service PostgreSQL database and the existing panel owner credentials.
Never creates/edits service orders: device intake remains on Android with camera/OCR.
"""
from __future__ import annotations

import html
import uuid
from decimal import Decimal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from app.database import engine
from app.routers.multiguard_license import _panel_auth, _panel_html

router = APIRouter(tags=["multiservis-owner-web"])

def esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)

def money(value: object) -> str:
    try:
        return f"{Decimal(value or 0):,.2f}".replace(",", " ").replace(".", ",") + " zł"
    except (ValueError, TypeError):
        return "—"

def dt(value: object) -> str:
    if value is None:
        return "—"
    try:
        return value.strftime("%d.%m.%Y %H:%M")
    except AttributeError:
        return esc(value)

def page(content: str) -> HTMLResponse:
    return HTMLResponse(
        content=_panel_html(content),
        headers={"Cache-Control": "private, no-store", "X-Frame-Options": "DENY"},
    )

_STATUS = {
    "all": ("Wszystkie zlecenia", ""),
    "active": ("W trakcie naprawy", "s.status='IN_SERVICE'"),
    "ready": ("Gotowe do odbioru", "s.status='READY_FOR_PICKUP'"),
    "completed": ("Wydane", "s.status='COMPLETED'"),
    "cancelled": ("Anulowane", "s.status='CANCELLED'"),
}

def status_badge(status: object) -> str:
    key = str(status or "")
    labels = {
        "IN_SERVICE": ("W naprawie", "mg-blue"),
        "READY_FOR_PICKUP": ("Do odbioru", "mg-gold"),
        "COMPLETED": ("Wydane", "mg-green"),
        "CANCELLED": ("Anulowane", "mg-red"),
    }
    label, css = labels.get(key, (key or "—", ""))
    return f'<span class="badge {css}">{esc(label)}</span>'


@router.get("/multiguard/panel/service", response_class=HTMLResponse)
def service_orders(
    status: str = Query("all"),
    q: str = Query("", max_length=120),
    page_number: int = Query(1, ge=1, le=5000),
    _: None = Depends(_panel_auth),
):
    if status not in _STATUS:
        raise HTTPException(400, "Nieprawidłowy filtr zleceń.")
    where = []
    params: dict[str, object] = {}
    if _STATUS[status][1]:
        where.append(_STATUS[status][1])
    query = q.strip()
    if query:
        where.append("""
            (s.reception_number ILIKE :query OR s.display_name ILIKE :query
             OR s.model ILIKE :query OR s.manufacturer ILIKE :query
             OR s.serial_number ILIKE :query OR s.phone_e164 ILIKE :query)
        """)
        params["query"] = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    # Guard against wildcard expansion and unbounded browser lists.
    sql = f"""
        SELECT s.id,s.reception_number,s.status,s.received_at,s.completed_at,
               s.manufacturer,s.model,s.serial_number,s.device_type,
               s.display_name,s.phone_e164,
               COALESCE(f.service_amount,0) AS service_amount,
               COALESCE(f.material_cost,0) AS material_cost
        FROM service.v_service_order_summary s
        LEFT JOIN service.owner_finances f ON f.service_order_id=s.id
        {where_sql}
        ORDER BY s.received_at DESC
        LIMIT 41 OFFSET :offset
    """
    with engine.connect() as con:
        counts = con.execute(text("""
            SELECT count(*) AS all_count,
                   count(*) FILTER (WHERE status='IN_SERVICE') AS active,
                   count(*) FILTER (WHERE status='READY_FOR_PICKUP') AS ready,
                   count(*) FILTER (WHERE status='COMPLETED') AS completed,
                   count(*) FILTER (WHERE status='CANCELLED') AS cancelled
            FROM service.service_orders
        """)).mappings().one()
        finance = con.execute(text("""
            SELECT COALESCE(sum(f.service_amount),0) AS revenue,
                   COALESCE(sum(f.material_cost),0) AS costs,
                   COALESCE(sum(f.service_amount-f.material_cost),0) AS profit
            FROM service.service_orders s
            JOIN service.owner_finances f ON f.service_order_id=s.id
            WHERE s.status='COMPLETED'
              AND s.completed_at >= (date_trunc('month', now() AT TIME ZONE 'Europe/Warsaw') AT TIME ZONE 'Europe/Warsaw')
        """)).mappings().one()
        rows = con.execute(text(sql), {**params, "offset": (page_number-1)*40}).mappings().all()
    has_more = len(rows) > 40
    rows = rows[:40]
    metrics = [
        ("Aktywne", counts["active"], "/multiguard/panel/service?status=active", "blue"),
        ("Do odbioru", counts["ready"], "/multiguard/panel/service?status=ready", "gold"),
        ("Wydane", counts["completed"], "/multiguard/panel/service?status=completed", "green"),
        ("Wszystkie", counts["all_count"], "/multiguard/panel/service", "red"),
    ]
    cards = "".join(
        f'<a class="metric metric-link accent-{tone}" href="{url}"><b>{esc(label)}</b><strong>{int(value or 0)}</strong><small>Przejdź do listy →</small></a>'
        for label,value,url,tone in metrics
    )
    finance_cards = "".join(
        f'<div class="metric accent-{tone}"><b>{esc(title)}</b><strong class="money">{money(value)}</strong></div>'
        for title,value,tone in [
            ("Przychód z wydań · miesiąc",finance["revenue"],"gold"),
            ("Koszty wydanych · miesiąc",finance["costs"],"red"),
            ("Wynik z wydanych · miesiąc",finance["profit"],"green"),
        ]
    )
    tab_html = "".join(
        f'<a class="filter-tab {"selected" if status==key else ""}" href="/multiguard/panel/service?{urlencode({"status":key,"q":query})}">{esc(label)}</a>'
        for key,(label,_) in _STATUS.items()
    )
    trs = []
    for row in rows:
        model = " ".join(x for x in [row["manufacturer"],row["model"]] if x) or row["device_type"] or "Urządzenie"
        trs.append(f"""
        <tr>
          <td><a class="strong-link" href="/multiguard/panel/service/{row['id']}">{esc(row['reception_number'])}</a></td>
          <td>{status_badge(row['status'])}</td>
          <td><strong>{esc(model)}</strong><small class="row-sub">{esc(row['serial_number'] or '—')}</small></td>
          <td>{esc(row['display_name'] or '—')}<small class="row-sub">{esc(row['phone_e164'] or '')}</small></td>
          <td class="numbers">{dt(row['received_at'])}</td>
          <td class="numbers">{dt(row['completed_at'])}</td>
          <td class="numbers">{money(row['service_amount']) if row['status']=='COMPLETED' else '—'}</td>
          <td><a class="button-link compact" href="/multiguard/panel/service/{row['id']}">PODGLĄD</a></td>
        </tr>""")
    table = "".join(trs) or '<tr><td colspan="8" class="muted">Brak zleceń dla wybranych filtrów.</td></tr>'
    def link_for(n: int) -> str:
        return "/multiguard/panel/service?" + urlencode({"status":status,"q":query,"page_number":n})
    prev = f'<a class="button-link compact" href="{link_for(page_number-1)}">← Poprzednie</a>' if page_number>1 else ""
    nxt = f'<a class="button-link compact" href="{link_for(page_number+1)}">Następne →</a>' if has_more else ""
    return page(f"""
    <section class="card panel-hero service-hero">
      <div class="eyebrow">MULTI-SERVIS / SERWIS WŁAŚCICIELA</div>
      <h1>Zlecenia i statystyki</h1>
      <p>Podgląd rzeczywistych danych z tej samej bazy PostgreSQL co aplikacja Android. Bez modyfikowania zleceń.</p>
      <div class="metrics owner-kpis">{cards}</div>
    </section>
    <section class="card">
      <div class="section-head"><div><div class="eyebrow">FINANSE</div><h2>Wydania w bieżącym miesiącu</h2><p>Przychód liczony wyłącznie po faktycznym wydaniu urządzenia klientowi. Koszty dotyczą tutaj wydanych zleceń, a nie wszystkich bieżących wydatków.</p></div></div>
      <div class="metrics">{finance_cards}</div>
    </section>
    <section class="card">
      <div class="section-head"><div><div class="eyebrow">ZLECENIA</div><h2>{esc(_STATUS[status][0])}</h2><p>Lista zleceń — 40 pozycji na stronę.</p></div></div>
      <div class="filter-tabs">{tab_html}</div>
      <form class="service-search" method="get" action="/multiguard/panel/service">
        <input type="hidden" name="status" value="{esc(status)}">
        <label>Wyszukaj numer, klienta, telefon, model lub numer seryjny<input name="q" maxlength="120" value="{esc(query)}" placeholder="np. MS-2026-..., Lenovo, +48..."></label>
        <button type="submit">SZUKAJ</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Numer</th><th>Status</th><th>Sprzęt</th><th>Klient</th><th>Przyjęto</th><th>Wydano</th><th>Przychód</th><th></th></tr></thead>
        <tbody>{table}</tbody>
      </table></div>
      <div class="pagination">{prev}<span>Strona {page_number}</span>{nxt}</div>
    </section>
    """)


@router.get("/multiguard/panel/service/{order_id}", response_class=HTMLResponse)
def service_order_detail(
    order_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    with engine.connect() as con:
        row = con.execute(text("""
            SELECT s.*, COALESCE(f.service_amount,0) AS service_amount,
                   COALESCE(f.material_cost,0) AS material_cost,
                   COALESCE(f.donor_material_value,0) AS donor_material_value,
                   COALESCE(f.service_amount-f.material_cost,0) AS actual_profit,
                   so.intake_description,so.fault_description,
                   so.technician_notes,so.customer_notes,so.accessories_received
            FROM service.v_service_order_summary s
            JOIN service.service_orders so ON so.id=s.id
            LEFT JOIN service.owner_finances f ON f.service_order_id=s.id
            WHERE s.id=:id
            LIMIT 1
        """),{"id":order_id}).mappings().first()
        if not row:
            raise HTTPException(404, "Nie znaleziono zlecenia.")
        history=con.execute(text("""
            SELECT old_status,new_status,changed_at FROM service.service_order_status_history
            WHERE service_order_id=:id ORDER BY changed_at DESC LIMIT 25
        """),{"id":order_id}).mappings().all()
        media=con.execute(text("""
            SELECT m.media_kind,o.original_filename,m.caption,m.created_at FROM service.service_order_media m
            JOIN core.storage_objects o ON o.id=m.storage_object_id
            WHERE m.service_order_id=:id AND m.deleted_at IS NULL
              AND o.deleted_at IS NULL
            ORDER BY m.sort_order,m.created_at DESC LIMIT 50
        """),{"id":order_id}).mappings().all()
    def fact(label: str, value: object) -> str:
        return f'<div class="detail-fact"><b>{esc(label)}</b><span>{esc(value or "—")}</span></div>'
    facts="".join([
        fact("Klient",row["display_name"]),
        fact("Telefon",row["phone_e164"]),
        fact("Sprzęt"," ".join(x for x in [row["manufacturer"],row["model"]] if x)),
        fact("Numer seryjny",row["serial_number"]),
        fact("Przyjęto",dt(row["received_at"])),
        fact("Gotowe do odbioru",dt(row["ready_at"])),
        fact("Wydano",dt(row["completed_at"])),
    ])
    def note(label: str,value: object) -> str:
        return f'<div class="detail-note"><strong>{esc(label)}</strong><p>{esc(value or "—")}</p></div>'
    notes="".join([
        note("Opis przyjęcia",row["intake_description"]),
        note("Usterka",row["fault_description"]),
        note("Uwagi techniczne",row["technician_notes"]),
        note("Uwagi dla klienta",row["customer_notes"]),
        note("Akcesoria",row["accessories_received"]),
    ])
    hist="".join(f'<tr><td>{dt(x["changed_at"])}</td><td>{status_badge(x["old_status"])}</td><td>→</td><td>{status_badge(x["new_status"])}</td></tr>' for x in history)
    media_rows="".join(f'<tr><td>{esc(x["media_kind"])}</td><td>{esc(x["original_filename"])}</td><td>{esc(x["caption"])}</td><td>{dt(x["created_at"])}</td></tr>' for x in media)
    fin=[("Kwota usługi",row["service_amount"]),("Koszt materiałów",row["material_cost"]),("Wartość dawcy",row["donor_material_value"]),("Wynik",row["actual_profit"])]
    fin_cards="".join(f'<div class="metric"><b>{esc(k)}</b><strong class="money">{money(v)}</strong></div>' for k,v in fin)
    return page(f"""
    <section class="card panel-hero">
      <a class="button-link compact" href="/multiguard/panel/service">← WRÓĆ DO ZLECEŃ</a>
      <div class="eyebrow" style="margin-top:14px">KARTA SERWISOWA</div>
      <h1>{esc(row["reception_number"])} {status_badge(row["status"])}</h1>
      <p>Podgląd właściciela, bez edycji danych. Przyjmowanie urządzeń ze zdjęciami pozostaje w aplikacji Android.</p>
      <div class="detail-facts">{facts}</div>
    </section>
    <section class="card"><h2>Opis i notatki</h2><div class="notes-grid">{notes}</div></section>
    <section class="card"><h2>Finanse zlecenia</h2><div class="metrics">{fin_cards}</div><p>Przychód i wynik pojawiają się w statystykach zrealizowanych usług dopiero po statusie „Wydany”.</p></section>
    <section class="card"><h2>Historia statusów</h2><div class="table-wrap"><table><thead><tr><th>Data</th><th>Poprzedni</th><th></th><th>Nowy</th></tr></thead><tbody>{hist or '<tr><td colspan="4">Brak historii.</td></tr>'}</tbody></table></div></section>
    <section class="card"><h2>Dokumentacja multimedialna ({len(media)})</h2><p>Wykaz zdjęć i dokumentów — bez pobierania ich do przeglądarki. Podgląd pełnych obrazów pozostaje w aplikacji mobilnej do czasu przygotowania bezpiecznego dostępu WWW.</p><div class="table-wrap"><table><thead><tr><th>Typ</th><th>Plik</th><th>Opis</th><th>Data</th></tr></thead><tbody>{media_rows or '<tr><td colspan="4">Brak plików.</td></tr>'}</tbody></table></div></section>
    """)


# Release log: only records committed to the Multi-Servis release catalog
# are shown. No invented changelog entries based on version numbers.
_RELEASE_CATEGORIES = {
    "ADDED": ("Dodano", "mg-green"),
    "FIXED": ("Naprawiono", "mg-blue"),
    "CHANGED": ("Zmieniono", "mg-gold"),
    "REMOVED": ("Usunięto", "mg-red"),
    "SECURITY": ("Bezpieczeństwo", "mg-red"),
    "DODANO": ("Dodano", "mg-green"),
    "NAPRAWIONO": ("Naprawiono", "mg-blue"),
    "ZMIENIONO": ("Zmieniono", "mg-gold"),
    "USUNIĘTO": ("Usunięto", "mg-red"),
}
def _changelog(notes: object) -> str:
    import re
    value = str(notes or "").strip()
    if not value:
        return '<p class="muted">Dla tego wydania nie zapisano jeszcze opisu zmian.</p>'
    lines = []
    for line in value.splitlines()[:150]:
        line = line.strip().lstrip("•*- ").strip()
        if not line:
            continue
        match = re.match(r"^(ADDED|FIXED|CHANGED|REMOVED|SECURITY|DODANO|NAPRAWIONO|ZMIENIONO|USUNIĘTO)\s*[:-]\s*(.+)$", line, re.I)
        if match:
            label, css = _RELEASE_CATEGORIES[match.group(1).upper()]
            lines.append(f'<li><span class="badge {css}">{label}</span> {esc(match.group(2))}</li>')
        else:
            lines.append(f'<li>{esc(line)}</li>')
    return '<ul class="release-changes">' + "".join(lines) + "</ul>" if lines else '<p class="muted">Brak opisu zmian.</p>'


@router.get("/multiguard/panel/versions", response_class=HTMLResponse)
def multiguard_release_history(
    _: None = Depends(_panel_auth),
):
    with engine.connect() as con:
        exists = con.execute(text("SELECT to_regclass('guard.release_versions') IS NOT NULL")).scalar_one()
        rows = []
        if exists:
            rows = con.execute(text("""
                SELECT version,channel,status,notes,rollout_percent,
                       rollback_safe,published_at,created_at
                FROM guard.release_versions
                WHERE channel IN ('PILOT','STABLE')
                ORDER BY published_at DESC NULLS LAST,created_at DESC
                LIMIT 100
            """)).mappings().all()
    entries=[]
    for row in rows:
        channel_label = "BETA" if row["channel"] == "PILOT" else "STABLE"
        accent = "mg-gold" if row["channel"] == "PILOT" else "mg-green"
        state = str(row["status"] or "DRAFT").upper()
        state_label = {
            "DRAFT": "Szkic — nieudostępniona",
            "AVAILABLE": "Dostępna",
            "PAUSED": "Wstrzymana",
            "RETIRED": "Archiwalna",
        }.get(state,state)
        entries.append(f"""
        <article class="release-card">
          <div class="section-head">
            <div>
              <div class="eyebrow">{esc(channel_label)} · {esc(row['version'])}</div>
              <h2>Multi-Guard {esc(row['version'])}</h2>
              <p>{esc(state_label)} • publikacja: {dt(row['published_at'])}</p>
            </div>
            <span class="badge {accent}">{esc(channel_label)}</span>
          </div>
          {_changelog(row['notes'])}
        </article>""")
    if not exists:
        notice = '<p class="muted">Katalog wydań nie istnieje jeszcze w bazie. Historia pojawi się po skonfigurowaniu serwera aktualizacji.</p>'
    elif not entries:
        notice = '<p class="muted">Nie zarejestrowano jeszcze wydań BETA/STABLE. Starsze wydania TEST nie są automatycznie przedstawiane jako STABLE.</p>'
    else:
        notice = "".join(entries)
    return page(f"""
    <section class="card panel-hero">
      <div class="eyebrow">MULTI-GUARD / HISTORIA ROZWOJU</div>
      <h1>Historia wersji BETA i STABLE</h1>
      <p>Co dodano, poprawiono, zmieniono lub usunięto w kolejnych wydaniach. Informacje pochodzą z katalogu aktualizacji na serwerze — bez wymyślania opisów zmian.</p>
    </section>
    <section class="card">
      <h2>Historia opublikowanych i przygotowywanych wersji</h2>
      <p>Wersja BETA może być udostępniona wybranym komputerom. STABLE wymaga osobnego zatwierdzenia właściciela.</p>
      <div class="release-timeline">{notice}</div>
    </section>
    """)
