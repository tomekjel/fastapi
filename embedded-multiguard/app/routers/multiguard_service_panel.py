"""OWNER service orders and financial statistics in Multi-Servis web.

The interface uses the same PostgreSQL figures as Android. Intake and camera/OCR
remain on Android. No customer data is sent to external dashboards.
"""
from __future__ import annotations

import html
import uuid
import time
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from decimal import Decimal
from pathlib import Path, PurePosixPath
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Form
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from sqlalchemy import text
from app.database import engine
from app.config import settings
from app.routers.multiguard_license import (_panel_auth, _panel_html,
    _normalize_link, _update_installation_mirror)
from app.routers.multiguard_panel_settings import _csrf_token, _token_valid

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

# Only raster formats may be displayed inside a browser. All other file
# types are offered for download, never rendered as active HTML/SVG.
_WEB_IMAGE_TYPES=frozenset({"image/jpeg","image/png","image/webp","image/gif"})
_MAX_INLINE_BYTES=16*1024*1024

GALLERY_WIDGET_HTML = r"""
<dialog class="photo-viewer" id="service-photo-viewer" aria-label="Przeglądarka zdjęć naprawy">
  <div class="viewer-top">
    <strong>Zdjęcia zlecenia</strong>
    <button type="button" class="viewer-close" aria-label="Zamknij zdjęcia">ZAMKNIJ ✕</button>
  </div>
  <div class="viewer-body">
    <button type="button" class="viewer-arrow viewer-prev" aria-label="Poprzednie zdjęcie">❮</button>
    <div class="viewer-viewport"><img class="viewer-image" alt="" draggable="false"></div>
    <button type="button" class="viewer-arrow viewer-next" aria-label="Następne zdjęcie">❯</button>
  </div>
  <div class="viewer-bottom">
    <span class="viewer-count" aria-live="polite"></span>
    <span class="viewer-caption"></span>
    <div class="viewer-zoom">
      <button type="button" class="viewer-zoom-out" aria-label="Oddal">−</button>
      <span class="viewer-zoom-label">100%</span>
      <button type="button" class="viewer-zoom-in" aria-label="Przybliż">＋</button>
      <button type="button" class="viewer-zoom-reset" aria-label="Resetuj powiększenie">1:1</button>
    </div>
  </div>
  <p class="viewer-hint">← / → — poprzednie i następne · + / − — powiększenie · Esc — zamknij · na telefonie przesuń palcem</p>
</dialog>
<script>
(() => {
  const modal = document.getElementById('service-photo-viewer');
  if (!modal || typeof modal.showModal !== 'function') return;
  const thumbnails = [...document.querySelectorAll('.gallery-thumb-link')];
  const photos = thumbnails.map(a => ({url:a.href, caption:a.dataset.galleryTitle||'Zdjęcie urządzenia'}));
  if (!photos.length) return;
  const image = modal.querySelector('.viewer-image');
  const caption = modal.querySelector('.viewer-caption');
  const counter = modal.querySelector('.viewer-count');
  const viewport = modal.querySelector('.viewer-viewport');
  const zoomLabel = modal.querySelector('.viewer-zoom-label');
  let index = 0;
  let zoom = 1;
  function applyZoom() {
    image.style.width = Math.round(zoom * 100) + '%';
    image.style.maxHeight = zoom === 1 ? '68vh' : 'none';
    zoomLabel.textContent = Math.round(zoom * 100) + '%';
  }
  function changeZoom(amount) {
    zoom = Math.max(1,Math.min(4,Math.round((zoom + amount) * 4)/4));
    applyZoom();
  }
  function show(n) {
    index = (n + photos.length) % photos.length;
    zoom = 1;
    image.src = photos[index].url;
    image.alt = photos[index].caption;
    caption.textContent = photos[index].caption;
    counter.textContent = (index+1) + ' / ' + photos.length;
    applyZoom();
    viewport.scrollTo(0,0);
  }
  for (const link of document.querySelectorAll('.gallery-open')) {
    link.addEventListener('click',event => {
      const pos = Number(link.dataset.galleryIndex);
      if (!Number.isInteger(pos) || pos < 0 || pos >= photos.length) return;
      event.preventDefault();
      show(pos);
      modal.showModal();
    });
  }
  modal.querySelector('.viewer-close').addEventListener('click',()=>modal.close());
  modal.querySelector('.viewer-prev').addEventListener('click',()=>show(index-1));
  modal.querySelector('.viewer-next').addEventListener('click',()=>show(index+1));
  modal.querySelector('.viewer-zoom-in').addEventListener('click',()=>changeZoom(.25));
  modal.querySelector('.viewer-zoom-out').addEventListener('click',()=>changeZoom(-.25));
  modal.querySelector('.viewer-zoom-reset').addEventListener('click',()=>{zoom=1;applyZoom()});
  modal.addEventListener('keydown',event=>{
    if (event.key === 'ArrowLeft') {event.preventDefault();show(index-1)}
    if (event.key === 'ArrowRight') {event.preventDefault();show(index+1)}
    if (event.key === '+' || event.key === '=') {event.preventDefault();changeZoom(.25)}
    if (event.key === '-') {event.preventDefault();changeZoom(-.25)}
    if (event.key === '0') {event.preventDefault();zoom=1;applyZoom()}
  });
  let sx=0,sy=0;
  viewport.addEventListener('touchstart',e=>{
    if(e.touches.length!==1)return;
    sx=e.touches[0].clientX;sy=e.touches[0].clientY;
  },{passive:true});
  viewport.addEventListener('touchend',e=>{
    if(e.changedTouches.length!==1)return;
    const dx=e.changedTouches[0].clientX-sx;
    const dy=e.changedTouches[0].clientY-sy;
    if(Math.abs(dx)>55 && Math.abs(dx)>Math.abs(dy)*1.2) show(index+(dx<0?1:-1));
  },{passive:true});
})();
</script>
"""



def _media_file_path(object_key: str) -> Path:
    """Prevent path escape or symlink traversal outside Multi-Servis media_root."""
    if not isinstance(object_key,str) or not object_key:
        raise HTTPException(404,"Nie znaleziono pliku.")
    # Keys written by Multi-Servis are normalized, relative UNIX-style paths.
    raw=PurePosixPath(object_key)
    if raw.is_absolute() or ".." in raw.parts or "\\" in object_key:
        raise HTTPException(404,"Nie znaleziono pliku.")
    try:
        root=Path(settings.media_root).resolve(strict=True)
        candidate=(root/Path(*raw.parts)).resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(404,"Plik jest niedostępny.") from None
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise HTTPException(404,"Plik jest niedostępny.")
    return candidate


@router.get("/multiguard/panel/service/{order_id}/media/{media_id}")
def owner_order_media(
    order_id: uuid.UUID,
    media_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    # The order ID is required in the SQL join. Cross-order ID guessing must
    # never yield private media from another customer's repair.
    with engine.connect() as con:
        row=con.execute(text("""
            SELECT o.object_key,o.original_filename,o.mime_type,o.size_bytes
            FROM service.service_order_media m
            JOIN core.storage_objects o ON o.id=m.storage_object_id
            WHERE m.id=:media_id AND m.service_order_id=:order_id
              AND m.deleted_at IS NULL AND o.deleted_at IS NULL
            LIMIT 1
        """),{"media_id":media_id,"order_id":order_id}).mappings().first()
    if not row:
        raise HTTPException(404,"Nie znaleziono pliku tego zlecenia.")
    mime=str(row["mime_type"] or "").split(";",1)[0].lower().strip()
    can_inline=mime in _WEB_IMAGE_TYPES and 0 < int(row["size_bytes"] or 0) <= _MAX_INLINE_BYTES
    path=_media_file_path(row["object_key"])
    # Never trust original_filename as HTTP header content, even if it arrived
    # from a trusted Android client. Starlette FileResponse quotes it.
    filename=Path(str(row["original_filename"] or "dokument")).name
    return FileResponse(
        path,
        media_type=mime if can_inline else "application/octet-stream",
        filename=filename,
        content_disposition_type="inline" if can_inline else "attachment",
        headers={
            "Cache-Control":"private, no-store, max-age=0",
            "Pragma":"no-cache",
            "X-Content-Type-Options":"nosniff",
            "X-Frame-Options":"DENY",
            "Referrer-Policy":"no-referrer",
            "Content-Security-Policy":"default-src 'none'; sandbox",
        },
    )


_STATUS = {
    "active": ("W trakcie naprawy", "s.status='IN_SERVICE'"),
    "ready": ("Gotowe do odbioru", "s.status='READY_FOR_PICKUP'"),
    "completed": ("Wydane", "s.status='COMPLETED'"),
    "cancelled": ("Anulowane", "s.status='CANCELLED'"),
    "all": ("Wszystkie zlecenia", ""),
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
    status: str = Query("active"),
    q: str = Query("", max_length=120),
    page_number: int = Query(1, ge=1, le=5000),
    page_size: int = Query(20),
    _: None = Depends(_panel_auth),
):
    if status not in _STATUS:
        raise HTTPException(400, "Nieprawidłowy filtr zleceń.")
    if page_size not in (20, 50):
        raise HTTPException(400, "Dostępne rozmiary strony: 20 lub 50.")
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
               s.display_name,s.phone_e164
        FROM service.v_service_order_summary s
        {where_sql}
        ORDER BY s.received_at DESC
        LIMIT :limit OFFSET :offset
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
        rows = con.execute(text(sql), {**params, "limit": page_size + 1,
                                       "offset": (page_number-1)*page_size}).mappings().all()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
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
    tab_html = "".join(
        f'<a class="filter-tab {"selected" if status==key else ""}" href="/multiguard/panel/service?{urlencode({"status":key,"q":query,"page_size":page_size})}">{esc(label)}</a>'
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
          <td><a class="button-link compact" href="/multiguard/panel/service/{row['id']}">PODGLĄD</a></td>
        </tr>""")
    table = "".join(trs) or '<tr><td colspan="7" class="muted">Brak zleceń dla wybranych filtrów.</td></tr>'
    def link_for(n: int) -> str:
        return "/multiguard/panel/service?" + urlencode({"status":status,"q":query,"page_number":n,"page_size":page_size})
    prev = f'<a class="button-link compact" href="{link_for(page_number-1)}">← Poprzednie</a>' if page_number>1 else ""
    nxt = f'<a class="button-link compact" href="{link_for(page_number+1)}">Następne →</a>' if has_more else ""
    return page(f"""
    <section class="card panel-hero service-hero">
      <div class="eyebrow">MULTI-SERVIS / SERWIS WŁAŚCICIELA</div>
      <h1>Zlecenia serwisowe</h1>
      <p>Najpierw sprawy wymagające pracy. Finanse zbiorcze są wyłącznie w zakładce Statystyki.</p>
      <div class="metrics owner-kpis">{cards}</div>
    </section>
    <section class="card">
      <div class="section-head"><div><div class="eyebrow">ZLECENIA</div><h2>{esc(_STATUS[status][0])}</h2></div><div class="list-size-control"><a href="/multiguard/panel/service?{urlencode({"status":status,"q":query,"page_size":20})}" class="filter-tab {"selected" if page_size==20 else ""}">20</a><a href="/multiguard/panel/service?{urlencode({"status":status,"q":query,"page_size":50})}" class="filter-tab {"selected" if page_size==50 else ""}">50</a><span>na stronę</span></div></div>
      <div class="filter-tabs">{tab_html}</div>
      <form class="service-search" method="get" action="/multiguard/panel/service">
        <input type="hidden" name="status" value="{esc(status)}">
        <input type="hidden" name="page_size" value="{page_size}">
        <label>Wyszukaj numer, klienta, telefon, model lub numer seryjny<input name="q" maxlength="120" value="{esc(query)}" placeholder="np. MS-2026-..., Lenovo, +48..."></label>
        <button type="submit">SZUKAJ</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Numer</th><th>Status</th><th>Sprzęt</th><th>Klient</th><th>Przyjęto</th><th>Wydano</th><th></th></tr></thead>
        <tbody>{table}</tbody>
      </table></div>
      <div class="pagination">{prev}<span>Strona {page_number}</span>{nxt}</div>
    </section>
    """)



_WARSAW = ZoneInfo("Europe/Warsaw")


def _statistics_range(period: str, month: str, year: int, quarter: int,
                      from_date: str, to_date: str) -> tuple[datetime, datetime, str, str]:
    """Warsaw civil-day boundaries; completed orders use the same accounting date as Android."""
    now = datetime.now(_WARSAW)
    if period == "month":
        try:
            month_date = date.fromisoformat((month or now.strftime("%Y-%m")) + "-01")
        except ValueError as exc:
            raise HTTPException(400, "Podaj poprawny miesiąc RRRR-MM.") from exc
        first = month_date
        last = date(first.year + (first.month == 12), first.month % 12 + 1, 1)
        label = first.strftime("%m.%Y")
        # Monthly reports use the actual Warsaw handover day, not ISO
        # week starts (e.g. October's first week starts on 28 September).
        grouping = "day"
    elif period in ("quarter", "year"):
        y = year or now.year
        if not 2000 <= y <= 2100:
            raise HTTPException(400, "Nieprawidłowy rok.")
        if period == "quarter":
            q = quarter or ((now.month - 1)//3 + 1)
            if q not in (1, 2, 3, 4):
                raise HTTPException(400, "Kwartał musi mieścić się od 1 do 4.")
            first = date(y, (q-1)*3+1, 1)
            last = date(y + (q == 4), (q*3)%12+1, 1)
            label = f"{q}. kwartał {y}"
        else:
            first = date(y, 1, 1)
            last = date(y+1, 1, 1)
            label = str(y)
        grouping = "month"
    elif period == "custom":
        if not from_date and not to_date:
            first = now.date().replace(day=1)
            last_inclusive = now.date()
        else:
            try:
                first, last_inclusive = date.fromisoformat(from_date), date.fromisoformat(to_date)
            except ValueError as exc:
                raise HTTPException(400, "Podaj poprawny zakres dat.") from exc
        if first.year < 2000:
            raise HTTPException(400, "Zakres nie może zaczynać się przed rokiem 2000.")
        try:
            first, last_inclusive = date.fromisoformat(first.isoformat()), date.fromisoformat(last_inclusive.isoformat())
        except ValueError as exc:
            raise HTTPException(400, "Podaj poprawny zakres dat.") from exc
        if first > last_inclusive or (last_inclusive-first).days > 1826:
            raise HTTPException(400, "Nieprawidłowy okres (maksymalnie 5 lat).")
        last = last_inclusive + timedelta(days=1)
        label = f"{first:%d.%m.%Y} – {last_inclusive:%d.%m.%Y}"
        duration_days = (last-first).days
        grouping = "month" if duration_days > 90 else ("week" if duration_days > 62 else "day")
    else:
        raise HTTPException(400, "Nieprawidłowy okres statystyk.")
    return (
        datetime.combine(first, datetime.min.time(), tzinfo=_WARSAW),
        datetime.combine(last, datetime.min.time(), tzinfo=_WARSAW),
        label, grouping
    )


def _statistics_bucket_label(
    bucket: datetime, start: datetime, end: datetime,
    grouping: str, *, compact: bool = False,
) -> str:
    """Only display dates inside the OWNER-selected Warsaw reporting range.

    PostgreSQL's date_trunc('week') returns Monday even when it belongs to
    a previous month. The underlying SQL already filters issued orders by
    completed_at; the label must not imply that September was counted in an
    October report.
    """
    if grouping == "month":
        return bucket.strftime("%m.%Y")
    if grouping == "day":
        return bucket.strftime("%d.%m" if compact else "%d.%m.%Y")
    first = max(bucket.date(), start.date())
    last = min(bucket.date() + timedelta(days=6), end.date() - timedelta(days=1))
    fmt = "%d.%m" if compact else "%d.%m.%Y"
    if last <= first:
        return first.strftime(fmt)
    if first.month == last.month and first.year == last.year:
        return first.strftime("%d") + "–" + last.strftime(fmt)
    return first.strftime("%d.%m") + "–" + last.strftime(fmt)


@router.get("/multiguard/panel/statistics", response_class=HTMLResponse)
def service_statistics(
    period: str = Query("month"),
    month: str = Query("", max_length=7),
    year: int = Query(0),
    quarter: int = Query(0),
    from_date: str = Query("", max_length=10),
    to_date: str = Query("", max_length=10),
    _: None = Depends(_panel_auth),
):
    start, end, period_label, grouping = _statistics_range(
        period, month, year, quarter, from_date, to_date
    )
    query_params = {"start_at": start, "end_at": end}
    with engine.connect() as con:
        total = con.execute(text("""
            SELECT count(*) AS orders,
                   COALESCE(sum(f.service_amount),0) AS revenue,
                   COALESCE(sum(f.material_cost),0) AS material_cost,
                   COALESCE(sum(f.donor_material_value),0) AS donor_material_value,
                   COALESCE(sum(f.service_amount-f.material_cost),0) AS actual_profit,
                   COALESCE(sum(f.service_amount-f.material_cost-f.donor_material_value),0)
                       AS economic_profit
            FROM service.service_orders s
            LEFT JOIN service.owner_finances f ON f.service_order_id=s.id
            WHERE s.status='COMPLETED'
              AND s.completed_at >= :start_at AND s.completed_at < :end_at
        """), query_params).mappings().one()
        breakdown = con.execute(text("""
            SELECT date_trunc(:grouping, s.completed_at AT TIME ZONE 'Europe/Warsaw')
                       AS bucket,
                   count(*) AS orders,
                   COALESCE(sum(f.service_amount),0) AS revenue,
                   COALESCE(sum(f.material_cost),0) AS material_cost,
                   COALESCE(sum(f.donor_material_value),0) AS donor_material_value,
                   COALESCE(sum(f.service_amount-f.material_cost),0) AS actual_profit,
                   COALESCE(sum(f.service_amount-f.material_cost-f.donor_material_value),0)
                       AS economic_profit
            FROM service.service_orders s
            LEFT JOIN service.owner_finances f ON f.service_order_id=s.id
            WHERE s.status='COMPLETED'
              AND s.completed_at >= :start_at AND s.completed_at < :end_at
            GROUP BY bucket ORDER BY bucket
        """), {**query_params, "grouping": grouping}).mappings().all()

    # The number of issued orders is operational data and may be visible.
    # All monetary data below lives inside a closed <details> element.
    public_metrics = (
        '<div class="metric accent-blue"><b>Wydane zlecenia</b>'
        f'<strong>{int(total["orders"] or 0)}</strong></div>'
    )
    finance_items = [
        ("Przychód z usług", money(total["revenue"]), "green"),
        ("Koszt materiałów", money(total["material_cost"]), "red"),
        ("Materiał z dawcy", money(total["donor_material_value"]), "gold"),
        ("Zysk rzeczywisty", money(total["actual_profit"]), "blue"),
        ("Zysk ekonomiczny", money(total["economic_profit"]), "green"),
    ]
    finance_metrics = "".join(
        f'<div class="metric accent-{tone}"><b>{esc(label)}</b>'
        f'<strong class="money">{esc(value)}</strong></div>'
        for label,value,tone in finance_items
    )
    max_scale = max(
        [float(row["revenue"] or 0) for row in breakdown]
        + [float(row["material_cost"] or 0) for row in breakdown] + [1.0]
    )
    trend_rows = "".join(
        '<div class="finance-trend-row">'
        f'<span>{esc(_statistics_bucket_label(row["bucket"], start, end, grouping, compact=True))}</span>'
        '<div class="finance-trend-bars">'
        f'<i class="finance-trend-revenue" style="width:{max(0, float(row["revenue"] or 0))*100/max_scale:.1f}%"></i>'
        f'<i class="finance-trend-cost" style="width:{max(0, float(row["material_cost"] or 0))*100/max_scale:.1f}%"></i>'
        '</div>'
        f'<b>{money(row["revenue"])}</b></div>'
        for row in breakdown
    ) or '<p class="muted">W tym okresie nie ma wydanych zleceń. Nie pokazujemy fikcyjnych danych.</p>'
    report_rows = "".join(
        '<tr>'
        f'<td>{esc(_statistics_bucket_label(row["bucket"], start, end, grouping))}</td>'
        f'<td class="numbers">{int(row["orders"] or 0)}</td>'
        f'<td class="numbers">{money(row["revenue"])}</td>'
        f'<td class="numbers">{money(row["material_cost"])}</td>'
        f'<td class="numbers">{money(row["donor_material_value"])}</td>'
        f'<td class="numbers">{money(row["actual_profit"])}</td>'
        f'<td class="numbers">{money(row["economic_profit"])}</td>'
        '</tr>'
        for row in breakdown
    ) or '<tr><td colspan="7" class="muted">Brak danych dla tego okresu.</td></tr>'
    filters = "".join(
        f'<a class="filter-tab {"selected" if period==code else ""}" '
        f'href="/multiguard/panel/statistics?period={code}">{label}</a>'
        for code,label in (("month","Miesiąc"),("quarter","Kwartał"),
                           ("year","Rok"),("custom","Własny okres"))
    )
    month_selected = start.strftime("%Y-%m") if period == "month" else datetime.now(_WARSAW).strftime("%Y-%m")
    prev_month = (start.date().replace(day=1)-timedelta(days=1)).strftime("%Y-%m")
    next_month = end.strftime("%Y-%m")
    month_controls = (
        '<div class="statistics-period-controls">'
        f'<a class="button-link compact" href="/multiguard/panel/statistics?period=month&month={prev_month}" aria-label="Poprzedni miesiąc">←</a>'
        '<form method="get" action="/multiguard/panel/statistics">'
        '<input type="hidden" name="period" value="month">'
        f'<label>Miesiąc <input type="month" name="month" value="{month_selected}"></label>'
        '<button type="submit">Pokaż</button></form>'
        f'<a class="button-link compact" href="/multiguard/panel/statistics?period=month&month={next_month}" aria-label="Następny miesiąc">→</a>'
        '</div>'
    ) if period == "month" else ""
    selected_year = year or datetime.now(_WARSAW).year
    selected_quarter = quarter or (datetime.now(_WARSAW).month-1)//3+1
    if period in ("quarter", "year"):
        options = "".join(f'<option value="{n}" {"selected" if n==selected_year else ""}>{n}</option>' for n in range(datetime.now(_WARSAW).year+1, datetime.now(_WARSAW).year-7, -1))
        quarters = "".join(f'<option value="{n}" {"selected" if n==selected_quarter else ""}>{n}</option>' for n in range(1,5))
        month_controls = (
            '<form class="statistics-period-controls" method="get" action="/multiguard/panel/statistics">'
            f'<input type="hidden" name="period" value="{period}">'
            f'<label>Rok <select name="year">{options}</select></label>'
            + (f'<label>Kwartał <select name="quarter">{quarters}</select></label>' if period=="quarter" else "")
            + '<button type="submit">Pokaż</button></form>'
        )
    if period == "custom":
        month_controls = (
            '<form class="statistics-period-controls" method="get" action="/multiguard/panel/statistics">'
            '<input type="hidden" name="period" value="custom">'
            f'<label>Od <input name="from_date" type="date" required value="{start.date().isoformat()}"></label>'
            f'<label>Do <input name="to_date" type="date" required value="{(end.date()-timedelta(days=1)).isoformat()}"></label>'
            '<button type="submit">Pokaż</button></form>'
        )
    return page(f"""
      <section class="card panel-hero statistics-hero">
        <div class="eyebrow">MULTI-SERVIS / ANALITYKA WŁAŚCICIELA</div>
        <h1>Statystyki</h1>
        <p>Finanse wydanych napraw w okresie: <strong>{esc(period_label)}</strong>. Zestawienie bazuje na rzeczywistych zleceniach Multi-Servis.</p>
        <div class="filter-tabs statistics-filter-tabs">{filters}</div>
        {month_controls}
      </section>
      <section class="card">
        <div class="section-head"><div><h2>Podsumowanie okresu</h2>
          <p>Wydania sprzętu są widoczne bez odsłaniania kwot.</p></div></div>
        <div class="metrics statistics-metrics">{public_metrics}</div>
      </section>
      <details class="card statistics-finance-disclosure" id="statistics-finances">
        <summary>
          <span>Finanse wybranego okresu</span>
          <span class="statistics-finance-hint">Poufne dane właściciela · rozwiń ▾</span>
        </summary>
        <div class="statistics-finance-content">
          <p>Przychody, koszty materiałów oraz zyski są księgowane w statystykach
             wyłącznie w dniu faktycznego wydania sprzętu klientowi.</p>
          <div class="metrics statistics-metrics">{finance_metrics}</div>
          <section class="statistics-trend">
            <div class="section-head"><div><h2>Przychody i koszty w czasie</h2>
              <p>Jasny pasek: przychód · czerwony: koszt zakupionych materiałów.</p></div></div>
            {trend_rows}
          </section>
          <details class="statistics-table-disclosure">
            <summary>Pełne zestawienie okresów ▾</summary>
            <div class="table-wrap"><table>
              <thead><tr><th>Okres</th><th>Zlecenia</th><th>Przychód</th><th>Materiały</th>
                <th>Dawca</th><th>Zysk rzeczywisty</th><th>Zysk ekonomiczny</th></tr></thead>
              <tbody>{report_rows}</tbody>
            </table></div>
          </details>
          <p class="statistics-footnote">W statystykach finansowych przychody i koszty
          są przypisane do daty faktycznego wydania sprzętu (status Wydane).
          To zestawienie operacyjne nie zastępuje ewidencji księgowej,
          która może uwzględniać wcześniejszą datę poniesienia wydatku.</p>
        </div>
      </details>
    """)


@router.post("/multiguard/panel/service/{order_id}/issue")
def issue_service_order_from_web(
    order_id: uuid.UUID,
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    """Issue equipment in one DB transaction, including an installed Guard.

    This route does not activate a paid licence. Client document acceptance
    remains the only way to start the purchased 3/6/12-month period.
    """
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Nieprawidłowe potwierdzenie wydania.")
    with engine.begin() as con:
        order = con.execute(text("""
            SELECT id,status FROM service.service_orders
            WHERE id=:id FOR UPDATE
        """), {"id":order_id}).mappings().first()
        if order is None:
            raise HTTPException(404, "Nie znaleziono zlecenia.")
        current = str(order["status"])
        if current not in ("READY_FOR_PICKUP","COMPLETED"):
            raise HTTPException(409, "Wydanie wymaga statusu GOTOWE DO ODBIORU.")
        if current == "READY_FOR_PICKUP":
            # Lifecycle DB trigger writes completed_at, released_at and audit.
            con.execute(text("""
                UPDATE service.service_orders
                SET status='COMPLETED'
                WHERE id=:id AND status='READY_FOR_PICKUP'
            """), {"id":order_id})
        # Not every service order has Multi-Guard: release must still work.
        link_row = con.execute(text("""
            SELECT * FROM guard.license_links
            WHERE reception_id=:id FOR UPDATE
        """), {"id":order_id}).mappings().first()
        if link_row is not None:
            link = _normalize_link(dict(link_row))
            if link["lifecycle"] == "SERVICE_TEST" and link.get("installation_id"):
                new_row = con.execute(text("""
                    UPDATE guard.license_links
                    SET lifecycle='PENDING_ACCEPTANCE',
                        approved_at=COALESCE(approved_at,now()),
                        updated_at=now()
                    WHERE id=:id AND lifecycle='SERVICE_TEST'
                    RETURNING *
                """), {"id":link["id"]}).mappings().first()
                if new_row:
                    _update_installation_mirror(con, _normalize_link(dict(new_row)))
    # PRG: refresh will not repeat the operation if owner reloads the page.
    return RedirectResponse(
        f"/multiguard/panel/service/{order_id}?issued=1",
        status_code=303,
        headers={"Cache-Control":"private, no-store"},
    )


@router.get("/multiguard/panel/service/{order_id}", response_class=HTMLResponse)
def service_order_detail(
    order_id: uuid.UUID,
    issued: int = Query(0),
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
            SELECT m.id,m.media_kind,o.original_filename,o.mime_type,o.size_bytes,m.caption,m.created_at FROM service.service_order_media m
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
    photo_positions = {}
    for candidate in media:
        candidate_mime = str(candidate["mime_type"] or "").split(";",1)[0].strip().lower()
        if candidate_mime in _WEB_IMAGE_TYPES and 0 < int(candidate["size_bytes"] or 0) <= _MAX_INLINE_BYTES:
            photo_positions[str(candidate["id"])] = len(photo_positions)

    def media_row(x: object) -> str:
        url=f"/multiguard/panel/service/{order_id}/media/{x['id']}"
        photo_index=photo_positions.get(str(x["id"]))
        eligible=photo_index is not None
        title=esc(x["caption"] or x["original_filename"] or "Zdjęcie urządzenia")
        preview=(
            f'<a class="gallery-open gallery-thumb-link" href="{url}" data-gallery-index="{photo_index}" '
            f'data-gallery-title="{title}" aria-label="Otwórz galerię: {title}">'
            f'<img class="media-thumb" src="{url}" loading="lazy" alt="{title}"></a>'
            if eligible else '<span class="muted">DOKUMENT</span>'
        )
        action=("OTWÓRZ W GALERII" if eligible else "POBIERZ PLIK")
        controls=(f' class="button-link compact gallery-open" data-gallery-index="{photo_index}"'
                  if eligible else ' class="button-link compact"')
        return (f'<tr><td>{preview}</td><td>{esc(x["media_kind"])}</td>'
                f'<td>{esc(x["original_filename"])}</td><td>{esc(x["caption"])}</td>'
                f'<td>{dt(x["created_at"])}</td>'
                f'<td><a{controls} href="{url}">'
                f'{action}</a></td></tr>')
    media_rows="".join(media_row(x) for x in media)
    issue_action = ""
    if row["status"] == "READY_FOR_PICKUP":
        token = _csrf_token(int(time.time() // 3600))
        issue_action = f"""
        <section class="card service-release-card">
          <div class="section-head"><div><div class="eyebrow">ODBIÓR SPRZĘTU</div>
            <h2>Potwierdź faktyczne wydanie klientowi</h2>
            <p>Kwoty pozostają w zwiniętych finansach. Wydanie kończy
               Tryb serwisowy Multi-Guard, ale nie uruchamia licznika licencji.</p>
          </div><form method="post" action="/multiguard/panel/service/{order_id}/issue"
              class="release-confirm-form"
              onsubmit="return confirm('Czy sprzęt został faktycznie wydany klientowi?');">
            <input type="hidden" name="csrf_token" value="{token}">
            <button type="submit">✓ WYDANO SPRZĘT</button>
          </form></div>
        </section>"""
    elif issued and row["status"] == "COMPLETED":
        issue_action = ('<p class="notice-success" role="status">'
                        'Wydanie sprzętu zostało zapisane. Multi-Guard oczekuje'
                        ' teraz na akceptację dokumentów klienta, jeśli przypisano licencję.'
                        '</p>')

    fin=[("Kwota usługi",row["service_amount"]),
         ("Koszt materiałów",row["material_cost"]),
         ("Wartość materiałów z dawcy",row["donor_material_value"]),
         ("Zysk rzeczywisty",row["actual_profit"]),
         ("Zysk ekonomiczny",(row["actual_profit"] or Decimal(0)) - (row["donor_material_value"] or Decimal(0)))]
    fin_cards="".join(f'<div class="metric"><b>{esc(k)}</b><strong class="money">{money(v)}</strong></div>' for k,v in fin)
    return page(f"""
    <section class="card panel-hero device-hero">
      <a class="button-link compact" href="/multiguard/panel/service">← WRÓĆ DO ZLECEŃ</a>
      <div class="eyebrow" style="margin-top:14px">KARTA SERWISOWA</div>
      <h1>{esc(row["reception_number"])} {status_badge(row["status"])}</h1>
      <p>Podgląd właściciela, bez edycji danych. Przyjmowanie urządzeń ze zdjęciami pozostaje w aplikacji Android.</p>
      <div class="detail-facts">{facts}</div>
    </section>
    {issue_action}
    <section class="card"><h2>Opis i notatki</h2><div class="notes-grid">{notes}</div></section>
    <details class="card finance-disclosure"><summary><span>Finanse zlecenia</span><span class="finance-disclosure-hint">Dane właściciela · kliknij, aby rozwinąć ▾</span></summary><div class="metrics">{fin_cards}</div><p>Kwota usługi jest uwzględniana w zestawieniu wydanych zleceń dopiero po wydaniu sprzętu.</p></details>
    <section class="card"><h2>Historia statusów</h2><div class="table-wrap"><table><thead><tr><th>Data</th><th>Poprzedni</th><th></th><th>Nowy</th></tr></thead><tbody>{hist or '<tr><td colspan="4">Brak historii.</td></tr>'}</tbody></table></div></section>
    <section class="card"><h2>Zdjęcia i dokumenty ({len(media)})</h2><p>Chroniony podgląd właściciela: miniatury obrazów i pobieranie pozostałych plików. Materiały są odczytywane wyłącznie ze zlecenia, nie zapisujemy ich w publicznym katalogu WWW.</p><div class="table-wrap"><table><thead><tr><th>Podgląd</th><th>Rodzaj</th><th>Plik</th><th>Opis</th><th>Data</th><th>Otwórz</th></tr></thead><tbody>{media_rows or '<tr><td colspan="6">Brak plików.</td></tr>'}</tbody></table></div></section>
    {GALLERY_WIDGET_HTML if photo_positions else ""}
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
    <section class="card panel-hero license-hero">
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
