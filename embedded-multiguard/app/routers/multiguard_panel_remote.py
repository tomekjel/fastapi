"""Compact, read-only OWNER remote assistance workspace.

No remote sessions are opened by this view. The visible list is limited to
signed PRO commercial entitlements and enabled PRO workshop grants.
Short computer IDs are a UI locator only; operations MUST use full UUIDs.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from app.database import engine
from app.routers.multiguard_license import (
    _ensure_schema as _ensure_license_schema,
    _panel_auth,
    _panel_html,
)

router = APIRouter(tags=["multiguard-owner-remote-console"])


def _e(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _short_id(installation_id: Any) -> str:
    return "MG-" + str(installation_id).replace("-", "")[:8].upper()


def _recent(value: Any) -> bool:
    if not isinstance(value, datetime):
        return False
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return 0 <= (datetime.now(timezone.utc) - aware).total_seconds() <= 10 * 60


def _remote_candidates():
    """Both grant stores: workshop first, then paid PRO; no Standard entries."""
    _ensure_license_schema()
    with engine.connect() as con:
        workshop = con.execute(text("""
            SELECT pi.installation_id,
                   pi.manufacturer,pi.model,pi.hostname,pi.last_seen_at,
                   pi.first_seen_at, 'WORKSHOP' AS source
            FROM guard.pending_installations pi
            JOIN guard.workshop_grants wg
              ON wg.installation_id=pi.installation_id AND wg.enabled=TRUE
            WHERE wg.edition='PRO'
              AND pi.status IN ('WAITING','IGNORED')
            ORDER BY pi.first_seen_at DESC
            LIMIT 500
        """)).mappings().all()
        paid = con.execute(text("""
            SELECT gi.installation_external_id AS installation_id,
                   COALESCE(d.manufacturer,pi.manufacturer) AS manufacturer,
                   COALESCE(d.model,pi.model) AS model,
                   COALESCE(d.hostname,pi.hostname) AS hostname,
                   gi.last_seen_at, gi.created_at AS first_seen_at,
                   'CLIENT' AS source
            FROM guard.installations gi
            LEFT JOIN guard.pending_installations pi
              ON pi.installation_id=gi.installation_external_id
            LEFT JOIN core.devices d ON d.id=gi.service_device_id
            WHERE gi.is_current=TRUE AND gi.plan_code='PRO'
              AND gi.lifecycle='ACTIVE'
            ORDER BY gi.created_at DESC
            LIMIT 500
        """)).mappings().all()
    seen=set()
    results=[]
    for row in [*workshop,*paid]:
        uid=str(row["installation_id"])
        if uid in seen:
            continue
        seen.add(uid)
        manufacturer=str(row["manufacturer"] or "").strip()
        model=str(row["model"] or "").strip()
        label=(" ".join(x for x in (manufacturer,model) if x)
               or str(row["hostname"] or "").strip() or "Komputer")
        results.append({"uuid":uid,"short":_short_id(uid),"name":label,
                        "recent":_recent(row["last_seen_at"]),
                        "source":row["source"]})
    return results


REMOTE_LAYOUT_CSS = """
/* Wide-screen workspace, not a stack of cards. Each device is ONE line. */
.owner-remote-layout{display:grid;grid-template-columns:minmax(340px,29%) minmax(0,1fr);
    gap:12px;align-items:stretch;min-height:min(76vh,760px)}
.owner-remote-list,.owner-remote-screen{min-width:0;border:1px solid rgba(73,139,186,.40);
    border-radius:12px;background:rgba(7,22,37,.62);overflow:hidden}
.owner-remote-list{display:flex;flex-direction:column}
.owner-remote-list-header{display:flex;flex-direction:column;gap:9px;
    padding:12px;border-bottom:1px solid rgba(79,146,191,.30)}
.owner-remote-list-header strong{font-size:15px;font-weight:500}
.owner-remote-search{width:100%;box-sizing:border-box;height:38px;min-height:38px;
    border-radius:7px;border:1px solid rgba(88,167,203,.6);background:#071b2b;
    padding:8px 11px;color:#f4f8fb;font-size:13px}
.owner-remote-search:focus-visible{outline:2px solid #e9bc64}
.owner-remote-devices{overflow-y:auto;max-height:min(68vh,700px);padding:5px}
.owner-remote-device{display:grid;grid-template-columns:12px 105px minmax(0,1fr);
    gap:7px;align-items:center;min-height:42px;width:100%;padding:6px 8px;
    border:0;border-bottom:1px solid rgba(84,137,169,.17);border-radius:6px;
    background:transparent;color:#eaf4ff;text-align:left;cursor:pointer}
.owner-remote-device[hidden]{display:none!important}
.owner-remote-device:hover,.owner-remote-device.is-selected{background:rgba(29,102,148,.24)}
.owner-remote-device.is-selected{outline:1px solid rgba(224,176,74,.48)}
.owner-remote-device>code{font-size:12px;color:#e8c27c;white-space:nowrap;
    font-family:Consolas,monospace;font-weight:400}
.owner-remote-device-name{min-width:0;overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap;font-size:12px}
.owner-remote-presence{height:8px;width:8px;border-radius:50%;background:#788c9f}
.owner-remote-presence.recent{background:#39db98}
.owner-remote-empty{padding:20px 12px;color:#b4cadc;text-align:center}
.owner-remote-screen{display:flex;flex-direction:column}
.owner-remote-screen-header{display:flex;align-items:center;gap:10px;justify-content:space-between;
    padding:9px 13px;min-height:47px;border-bottom:1px solid rgba(72,141,190,.28)}
.owner-remote-screen-header strong{font-size:15px;font-weight:500}
.owner-remote-view{flex:1;min-height:350px;display:grid;place-items:center;
    background:radial-gradient(ellipse at center,rgba(11,57,91,.34),rgba(2,13,25,.9))}
.owner-remote-notice{padding:22px;text-align:center;max-width:460px}
.owner-remote-notice strong{display:block;font-size:18px;font-weight:500;color:#e9f6ff}
.owner-remote-notice p{font-size:12px;color:#aac4d6;line-height:1.5;margin:9px 0 0}
.owner-remote-tools{min-height:45px;display:flex;align-items:center;justify-content:flex-end;
    gap:10px;flex-wrap:wrap;padding:7px 12px;border-top:1px solid rgba(72,141,190,.28)}
.owner-remote-tools button{min-height:30px;padding:4px 9px}
.owner-remote-tools .owner-remote-lock{display:flex;align-items:center;gap:5px;
    font-size:11px;color:#b0c6d7;white-space:nowrap}
.owner-remote-tools :disabled{opacity:.54;cursor:not-allowed}
.owner-remote-muted{font-size:11px;color:#9ab5c9}
@media(max-width:1050px){
  .owner-remote-layout{grid-template-columns:300px minmax(0,1fr)}
  .owner-remote-device{grid-template-columns:10px 95px minmax(0,1fr);gap:5px}
  .owner-remote-device>code{font-size:11px}
}
@media(max-width:760px){
  .owner-remote-layout{grid-template-columns:1fr}
  .owner-remote-devices{max-height:205px}
  .owner-remote-view{min-height:310px}
}
"""


@router.get("/multiguard/panel/remote", response_class=HTMLResponse)
def owner_remote_console(_: None = Depends(_panel_auth)):
    rows = _remote_candidates()
    items=[]
    for row in rows:
        items.append(
            '<button type="button" class="owner-remote-device" '
            f'data-search="{_e(row["short"]+" "+row["uuid"]+" "+row["name"])}" '
            f'data-id="{_e(row["short"])}" '
            f'data-name="{_e(row["name"])}" '
            f'data-uuid="{_e(row["uuid"])}" '
            f'data-recent="{int(row["recent"])}" '
            f'aria-label="{_e(row["short"]+" "+row["name"])}">'
            f'<i class="owner-remote-presence {"recent" if row["recent"] else ""}" '
            'aria-hidden="true"></i>'
            f'<code>{_e(row["short"])}</code>'
            f'<span class="owner-remote-device-name" title="{_e(row["name"])}">'
            f'{_e(row["name"])}</span></button>'
        )
    if not items:
        items.append('<p class="owner-remote-empty">Brak komputerów z aktywnym PRO.</p>')
    body = f"""
    <style>{REMOTE_LAYOUT_CSS}</style>
    <section class="card" style="padding:12px 15px;margin-bottom:10px">
      <div class="section-head" style="margin:0">
        <div><div class="eyebrow">MULTI-GUARD / POMOC ZDALNA</div>
        <h1 style="margin:3px 0">Zdalna pomoc</h1>
        <p style="margin:0">Komputery PRO, wyszukiwanie po ID i stanowisko sesji.</p></div>
      </div>
    </section>
    <section class="owner-remote-layout">
      <div class="owner-remote-list">
        <div class="owner-remote-list-header">
          <strong>Komputery ({len(rows)})</strong>
          <input id="owner-remote-search" class="owner-remote-search" type="search"
           autocomplete="off" maxlength="120"
           placeholder="Szukaj po ID lub modelu…"
           aria-label="Wyszukaj komputer po ID, marce lub modelu">
        </div>
        <div class="owner-remote-devices" id="owner-remote-devices" aria-label="Komputery PRO">
          {''.join(items)}
        </div>
      </div>
      <div class="owner-remote-screen">
        <div class="owner-remote-screen-header">
          <strong id="owner-remote-title">Wybierz komputer</strong>
          <button id="owner-remote-fullscreen" type="button" class="button-link compact"
            title="Powiększ obszar podglądu" aria-label="Pełny ekran podglądu">⛶ PEŁNY EKRAN</button>
        </div>
        <div class="owner-remote-view" id="owner-remote-view">
          <div class="owner-remote-notice" aria-live="polite">
            <strong id="owner-remote-message">Wybierz komputer z listy</strong>
            <p id="owner-remote-detail">ID i model są wyświetlane w jednej linii.
            Zdalna sesja wymaga zgody klienta i potwierdzonego MeshAgent.</p>
          </div>
        </div>
        <div class="owner-remote-tools">
          <span class="owner-remote-muted" id="owner-remote-status">Brak sesji</span>
          <label class="owner-remote-lock" title="Funkcja wymaga potwierdzonej obsługi MeshCentral">
            <input type="checkbox" disabled>
            Zablokuj mysz i klawiaturę klienta
          </label>
          <button type="button" disabled id="owner-remote-connect">POŁĄCZ</button>
          <button type="button" disabled id="owner-remote-end">ROZŁĄCZ</button>
        </div>
      </div>
    </section>
    <script>
    (() => {{
      const input = document.getElementById('owner-remote-search');
      const entries = [...document.querySelectorAll('.owner-remote-device')];
      const title = document.getElementById('owner-remote-title');
      const msg = document.getElementById('owner-remote-message');
      const detail = document.getElementById('owner-remote-detail');
      const status = document.getElementById('owner-remote-status');
      const normalize = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      const filter = () => {{
        const needle = normalize(input.value);
        let count=0;
        for(const el of entries) {{
          const found = normalize(el.dataset.search).includes(needle);
          el.hidden=!found;
          if(found)count++;
        }}
        status.textContent = count+' / '+entries.length+' komputerów';
      }};
      input.addEventListener('input', filter);
      for(const el of entries) el.addEventListener('click', () => {{
        for(const previous of entries) previous.classList.remove('is-selected');
        el.classList.add('is-selected');
        title.textContent=el.dataset.id+' · '+el.dataset.name;
        msg.textContent=el.dataset.name;
        detail.textContent='ID: '+el.dataset.id+
          '. Ostatni kontakt: '+(el.dataset.recent==='1'?'do 10 minut':'niepotwierdzony w ostatnich 10 minutach')+
          '. Wybór komputera nie uruchamia samoczynnie żadnego połączenia.';
        status.textContent='Wybrano '+el.dataset.id;
      }});
      document.getElementById('owner-remote-fullscreen')
        .addEventListener('click', () => {{
          const target=document.getElementById('owner-remote-view');
          if(document.fullscreenElement) return void document.exitFullscreen();
          if(target.requestFullscreen) void target.requestFullscreen();
        }});
    }})();
    </script>
    """
    return HTMLResponse(_panel_html(body), headers={"Cache-Control": "no-store"})
