"""Authenticated, opt-in cross-OEM GPU missing-utilization development reports.

Payload is strictly allowlisted. No hostnames, device serial numbers,
full PNP instance IDs, hardware GUIDs, user accounts, process lists,
URLs, screenshot, camera/microphone data or logs may be submitted.
"""
from __future__ import annotations
import json
import re
import threading
import uuid
from datetime import datetime,timezone
from typing import Any, Optional
from fastapi import APIRouter,Depends,HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel,Field
from sqlalchemy import text
from app.database import engine
from app.routers.multiguard_license import _panel_auth,_panel_html
from app.routers.multiguard_runtime import _ensure_schema as _runtime_schema,_require_agent
from app.routers.multiguard_workshop_remote import _authorized_pending

router=APIRouter(prefix="/multiguard",tags=["multiguard-gpu-development"])
_LOCK=threading.Lock()
_READY=False

class GpuReportBody(BaseModel):
    requestId: str = Field(min_length=8,max_length=100)
    eventId: uuid.UUID
    installationId: uuid.UUID
    deviceId: str = Field(min_length=16,max_length=128)
    installationCredential: Optional[str] = None
    discoveryCredential: Optional[str] = None
    report: dict[str,Any]

def _ensure_schema():
    global _READY
    if _READY:return
    _runtime_schema()
    with _LOCK:
        if _READY:return
        with engine.begin() as con:
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.gpu_diagnostics (
                    event_id UUID PRIMARY KEY,
                    installation_external_id UUID NOT NULL,
                    source TEXT NOT NULL CHECK(source IN ('WORKSHOP','CLIENT')),
                    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    app_version TEXT NOT NULL,
                    issue_code TEXT NOT NULL,
                    report JSONB NOT NULL
                )
            """))
            con.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_guard_gpu_diag_installation
                ON guard.gpu_diagnostics(installation_external_id,received_at DESC)
            """))
        _READY=True

def _safe_report(raw):
    if not isinstance(raw,dict):
        raise HTTPException(400,"Brak raportu GPU.")
    allowed={"schemaVersion","issueCode","appVersion","windowsBuild","gpuCount",
             "missingCount","gpuEngineCounterCount","gpuEngineLuidCount",
             "gpuEnginePhysicalCount","directxLuidMatchedCount","adapters"}
    if set(raw)-allowed:
        raise HTTPException(400,"Raport GPU zawiera niedozwolone pola.")
    if raw.get("schemaVersion")!=1 or raw.get("issueCode")!="GPU_LOAD_UNAVAILABLE":
        raise HTTPException(400,"Nieznany format problemu GPU.")
    if not isinstance(raw.get("appVersion"),str) or not re.fullmatch(r"[0-9A-Za-z.+-]{1,32}",raw["appVersion"]):
        raise HTTPException(400,"Nieprawidłowa wersja aplikacji.")
    if raw.get("windowsBuild") is not None and (not isinstance(raw["windowsBuild"],str) or
                    not re.fullmatch(r"[0-9.]{1,30}",raw["windowsBuild"])):
        raise HTTPException(400,"Nieprawidłowa wersja Windows.")
    for key in ("gpuCount","missingCount","gpuEngineCounterCount","gpuEngineLuidCount",
                "gpuEnginePhysicalCount","directxLuidMatchedCount"):
        n=raw.get(key)
        if type(n) is not int or n<0 or n>10000:
            raise HTTPException(400,f"Nieprawidłowe pole GPU: {key}.")
    if not 1 <= raw["missingCount"] <= raw["gpuCount"] <= 8:
        raise HTTPException(400,"Nieprawidłowa liczba GPU.")
    adapters=raw.get("adapters")
    if not isinstance(adapters,list) or len(adapters)!=raw["gpuCount"]:
        raise HTTPException(400,"Niespójna lista GPU.")
    missing=0
    names=re.compile(r"[\w .()\-+&,/]{1,120}",re.UNICODE)
    version=re.compile(r"[0-9A-Za-z.\-]{1,64}")
    hex4=re.compile(r"[0-9A-Fa-f]{4}")
    for gpu in adapters:
        if not isinstance(gpu,dict) or set(gpu)!={"name","kind","loadAvailable",
                    "temperatureAvailable","driverVersion","vendorId","deviceId"}:
            raise HTTPException(400,"Niedozwolone pola karty graficznej.")
        if not isinstance(gpu["name"],str) or not names.fullmatch(gpu["name"]):
            raise HTTPException(400,"Nieprawidłowa nazwa GPU.")
        if gpu["kind"] not in ("integrated","discrete","unknown"):
            raise HTTPException(400,"Nieprawidłowa klasyfikacja GPU.")
        if type(gpu["loadAvailable"]) is not bool or type(gpu["temperatureAvailable"]) is not bool:
            raise HTTPException(400,"Nieprawidłowa dostępność odczytu.")
        missing+=not gpu["loadAvailable"]
        for key,pattern in (("driverVersion",version),("vendorId",hex4),("deviceId",hex4)):
            v=gpu[key]
            if v is not None and (not isinstance(v,str) or not pattern.fullmatch(v)):
                raise HTTPException(400,f"Nieprawidłowe pole: {key}.")
    if missing!=raw["missingCount"]:
        raise HTTPException(400,"Niezgodna liczba brakujących odczytów.")
    if len(json.dumps(raw,ensure_ascii=False).encode("utf-8"))>8192:
        raise HTTPException(413,"Diagnostyka GPU przekracza 8 KB.")
    return raw

@router.post("/agent/gpu-diagnostics")
def agent_gpu_diagnostic(body:GpuReportBody):
    _ensure_schema()
    report=_safe_report(body.report)
    if bool(body.discoveryCredential)==bool(body.installationCredential):
        raise HTTPException(400,"Wymagany jeden właściwy rodzaj poświadczenia.")
    with engine.begin() as con:
        if body.discoveryCredential:
            _authorized_pending(con,body.installationId,body.deviceId,
                                body.discoveryCredential,require_pro=False)
            source="WORKSHOP"
        else:
            # Strictly commercial KeyGate-bound identity, untouched paid-auth contract.
            licensed=_require_agent(con,body.installationId,body.deviceId,body.installationCredential)
            acceptance=con.execute(text("""
                SELECT lifecycle,accepted_at FROM guard.installations
                WHERE id=:iid AND is_current=TRUE
            """),{"iid":licensed["id"]}).mappings().first()
            if not acceptance or acceptance["lifecycle"]!="ACTIVE" or not acceptance["accepted_at"]:
                raise HTTPException(403,"Raportowanie wymaga aktywnej licencji i akceptacji dokumentów.")
            source="CLIENT"
        result=con.execute(text("""
            INSERT INTO guard.gpu_diagnostics
              (event_id,installation_external_id,source,app_version,issue_code,report)
            VALUES(:eid,:iid,:source,:app,:code,CAST(:payload AS jsonb))
            ON CONFLICT(event_id) DO NOTHING
            RETURNING event_id
        """),{"eid":body.eventId,"iid":body.installationId,"source":source,
              "app":report["appVersion"],"code":report["issueCode"],
              "payload":json.dumps(report,ensure_ascii=False)}).scalar_one_or_none()
        if result is None:
            old=con.execute(text("""
                SELECT installation_external_id FROM guard.gpu_diagnostics
                WHERE event_id=:eid
            """),{"eid":body.eventId}).scalar_one()
            if old!=body.installationId:
                raise HTTPException(409,"ID raportu należy do innej instalacji.")
    return {"requestId":body.requestId,"accepted":True,
            "duplicate":result is None,"serverTime":datetime.now(timezone.utc).isoformat()}

@router.get("/panel/gpu-diagnostics",response_class=HTMLResponse)
def owner_gpu_diagnostics(_:None=Depends(_panel_auth)):
    _ensure_schema()
    from html import escape
    with engine.connect() as con:
        rows=con.execute(text("""
            SELECT installation_external_id,source,received_at,app_version,report
            FROM guard.gpu_diagnostics
            ORDER BY received_at DESC LIMIT 100
        """)).mappings().all()
    table=[]
    for row in rows:
        data=row["report"] or {}
        adapters=data.get("adapters",[])
        models=", ".join(str(v.get("name","")) for v in adapters if not v.get("loadAvailable"))
        iid="MG-"+str(row["installation_external_id"]).replace("-","")[:8].upper()
        table.append("<tr><td>"+escape(iid)+"</td><td>"+escape(str(row["source"]))+
            "</td><td>"+escape(str(row["received_at"]))+"</td><td>"+
            escape(str(row["app_version"]))+"</td><td>"+
            escape(models)+"</td><td>"+
            escape(str(data.get("gpuEngineCounterCount","—")))+"</td></tr>")
    return HTMLResponse(_panel_html("""
    <section class="card"><div class="eyebrow">MULTI-GUARD / DIAGNOSTYKA ROZWOJOWA</div>
    <h1>Brakujące odczyty obciążenia GPU</h1>
    <p>Wyłącznie techniczne informacje o kartach i sterownikach; pełne dane
    raportu dostępne w rejestrze diagnostycznym serwera.</p>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Tryb</th>
    <th>Otrzymano</th><th>Wersja</th><th>Brak obciążenia</th><th>Liczników GPU</th>
    </tr></thead><tbody>"""+("".join(table) or "<tr><td colspan='6'>Brak zgłoszeń.</td></tr>")+
    "</tbody></table></div></section>"),headers={"Cache-Control":"private, no-store"})
