#!/usr/bin/env python3
"""Real PostgreSQL + FastAPI TestClient test. No production credentials/data.

PostgreSQL fixture emulates only old Multi-Servis contract tables and injects
the ACTUAL embedded owner-panel routers against them. Code creates guard
tables with production DDL, then exercises HTTP Basic, historical service
data, photos, diagnostic drafts, mutations and CSRF end-to-end.
"""
from __future__ import annotations

import importlib
import os
import re
import sys
import tempfile
import types
import uuid
from pathlib import Path

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine,text

ROOT=Path(__file__).resolve().parents[1]
assert ROOT.name=="embedded-multiguard"
url=os.environ["OWNER_TEST_DATABASE_URL"]
assert any(x in url for x in ("127.0.0.1","localhost")), "Local postgres only; never test against live database"
engine=create_engine(url,pool_pre_ping=True)

# Runtime imports only the relevant non-Android modules. The database and
# settings interfaces are the same as Multi-Servis app.database/app.config.
app_pkg=types.ModuleType("app")
app_pkg.__path__=[str(ROOT/"app")]
routers_pkg=types.ModuleType("app.routers")
routers_pkg.__path__=[str(ROOT/"app"/"routers")]
sys.modules["app"]=app_pkg
sys.modules["app.routers"]=routers_pkg
db_mod=types.ModuleType("app.database");db_mod.engine=engine
sys.modules["app.database"]=db_mod
security=types.ModuleType("app.security")
security.CurrentUser=type("CurrentUser",(),{})
security.require_owner=lambda: security.CurrentUser()
security.require_staff=lambda: security.CurrentUser()
sys.modules["app.security"]=security
with tempfile.TemporaryDirectory(prefix="multiservis-panel-ci-media-") as media_root:
    config=types.ModuleType("app.config")
    config.settings=types.SimpleNamespace(media_root=media_root)
    sys.modules["app.config"]=config
    os.environ["MULTIGUARD_PANEL_USER"]="owner_ci"
    os.environ["MULTIGUARD_PANEL_PASSWORD"]="isolated-only-no-real-secret"

    with engine.begin() as db:
        for sql in [
            "CREATE EXTENSION IF NOT EXISTS pgcrypto",
            "CREATE SCHEMA IF NOT EXISTS core",
            "CREATE SCHEMA IF NOT EXISTS service",
            """CREATE TABLE IF NOT EXISTS core.devices(
                id UUID PRIMARY KEY, manufacturer TEXT,model TEXT,serial_number TEXT,
                hostname TEXT,device_type TEXT,last_seen TIMESTAMPTZ,
                is_online BOOLEAN,updated_at TIMESTAMPTZ DEFAULT now())""",
            """CREATE TABLE IF NOT EXISTS service.service_orders(
                id UUID PRIMARY KEY,device_id UUID REFERENCES core.devices(id),
                reception_number TEXT,status TEXT,received_at TIMESTAMPTZ,
                ready_at TIMESTAMPTZ,completed_at TIMESTAMPTZ,
                intake_description TEXT,fault_description TEXT,technician_notes TEXT,
                customer_notes TEXT,accessories_received TEXT)""",
            """CREATE TABLE IF NOT EXISTS service.owner_finances(
                service_order_id UUID PRIMARY KEY REFERENCES service.service_orders(id),
                service_amount NUMERIC(12,2),material_cost NUMERIC(12,2),
                donor_material_value NUMERIC(12,2))""",
            """CREATE TABLE IF NOT EXISTS core.storage_objects(
                id UUID PRIMARY KEY,object_key TEXT,original_filename TEXT,
                mime_type TEXT,size_bytes BIGINT,deleted_at TIMESTAMPTZ)""",
            """CREATE TABLE IF NOT EXISTS service.service_order_media(
                id UUID PRIMARY KEY,service_order_id UUID REFERENCES service.service_orders(id),
                storage_object_id UUID REFERENCES core.storage_objects(id),
                media_kind TEXT,caption TEXT,sort_order INTEGER,
                created_at TIMESTAMPTZ DEFAULT now(),deleted_at TIMESTAMPTZ)""",
            """CREATE TABLE IF NOT EXISTS service.service_order_status_history(
                service_order_id UUID REFERENCES service.service_orders(id),
                old_status TEXT,new_status TEXT,changed_at TIMESTAMPTZ)""",
            """CREATE OR REPLACE VIEW service.v_service_order_summary AS
                SELECT s.id,s.reception_number,s.status,s.received_at,s.completed_at,s.ready_at,
                       d.manufacturer,d.model,d.serial_number,d.device_type,
                       'Przykładowy klient'::text AS display_name,
                       '+48000000000'::text AS phone_e164
                FROM service.service_orders s JOIN core.devices d ON d.id=s.device_id"""
        ]:
            db.execute(text(sql))

    license=importlib.import_module("app.routers.multiguard_license")
    runtime=importlib.import_module("app.routers.multiguard_runtime")
    service=importlib.import_module("app.routers.multiguard_service_panel")
    settings=importlib.import_module("app.routers.multiguard_panel_settings")
    devices=importlib.import_module("app.routers.multiguard_panel_devices")
    triage=importlib.import_module("app.routers.multiguard_panel_triage")
    diagnostic=importlib.import_module("app.routers.multiguard_panel_diagnostics")

    # Real SQL initializers run against fresh ephemeral PostgreSQL.
    license._ensure_schema()
    runtime._ensure_schema()
    settings._schema()
    devices._schema()
    triage._schema()
    diagnostic._schema()
    for factory in (license._ensure_schema,runtime._ensure_schema,settings._schema,
                    devices._schema,triage._schema,diagnostic._schema):
        factory()  # verify repeat calls are idempotent

    pc_a=uuid.uuid4()
    pc_b=uuid.uuid4()
    install_a=uuid.uuid4()
    install_b=uuid.uuid4()
    order_a=uuid.uuid4()
    order_b=uuid.uuid4()
    media_a=uuid.uuid4()
    image_storage=uuid.uuid4()
    event_a=uuid.uuid4()

    folder=Path(media_root)/"repairs"
    folder.mkdir()
    photo=folder/"device.jpg"
    photo.write_bytes(b"\xff\xd8\xff\xe0" + b"demo JPEG test bytes")
    with engine.begin() as db:
        for dev in (pc_a,pc_b):
            db.execute(text("""
                INSERT INTO core.devices(id,manufacturer,model,serial_number,
                                         hostname,device_type)
                VALUES (:id,'Lenovo','T14','SAME-SERIAL','host-ci','LAPTOP')
            """),{"id":dev})
        for install,dev,edition in [(install_a,pc_a,"STANDARD"),(install_b,pc_b,"PRO")]:
            db.execute(text("""
              INSERT INTO guard.installations(
                id,service_device_id,installation_external_id,
                device_id_hash,credential_sha256,lifecycle,last_seen_at,plan_code,
                app_version)
              VALUES(:iid,:did,:ext,'test-dh',:cred,'ACTIVE',now(),:plan,'0.3.35')
            """),{"iid":install,"did":dev,"ext":uuid.uuid4(),
                  "cred":"1"*64,"plan":edition})
        for order,dev in [(order_a,pc_a),(order_b,pc_b)]:
            db.execute(text("""
              INSERT INTO service.service_orders(
                id,device_id,reception_number,status,received_at,
                completed_at,intake_description,fault_description,
                technician_notes,customer_notes,accessories_received)
              VALUES(:id,:did,:num,'COMPLETED',now(),now(),
                     'Przyjęto laptop','Restartuje się','Weryfikować WHEA','',
                     'Zasilacz')
            """),{"id":order,"did":dev,"num":f"CI-{str(order)[:8]}"})
            db.execute(text("""
              INSERT INTO service.owner_finances(
                service_order_id,service_amount,material_cost,donor_material_value)
              VALUES(:id,280,40,0)
            """),{"id":order})
        db.execute(text("""
            INSERT INTO core.storage_objects(id,object_key,original_filename,
                                             mime_type,size_bytes)
            VALUES(:id,'repairs/device.jpg','device.jpg','image/jpeg',:size)
        """),{"id":image_storage,"size":photo.stat().st_size})
        db.execute(text("""
            INSERT INTO service.service_order_media(
                id,service_order_id,storage_object_id,media_kind,caption,sort_order)
            VALUES(:id,:order_id,:sid,'DEVICE_PHOTO','Fotografia sprzętu',0)
        """),{"id":media_a,"order_id":order_a,"sid":image_storage})
        db.execute(text("""
            INSERT INTO guard.events(
                event_id,installation_id,event_type,severity,occurred_at,payload)
            VALUES(:eid,:iid,'WHEA_LOG','WARNING',now(),CAST(:payload AS jsonb))
        """),{"eid":event_a,"iid":install_a,"payload":'{"message":"WHEA test"}'})

    app=FastAPI()
    for mod in (license,runtime,service,settings,devices,triage,diagnostic):
        app.include_router(mod.router)
    c=TestClient(app,raise_server_exceptions=True)
    auth=("owner_ci","isolated-only-no-real-secret")
    def get(url,authorized=True):
        return c.get(url,auth=auth if authorized else None)
    def ensure(actual,expected,label):
        assert actual==expected, f"{label}: {actual}, expected {expected}"

    ensure(get("/multiguard/panel/service",False).status_code,401,"Private service list")
    ensure(get("/multiguard/panel/settings",False).status_code,401,"Private settings")
    ensure(get("/multiguard/panel/versions",False).status_code,401,"Private versions")
    ensure(get(f"/multiguard/panel/service/{order_a}/media/{media_a}",False).status_code,401,"Private media")
    ensure(get(f"/multiguard/panel/device/{install_a}",False).status_code,401,"Private device")
    ensure(get("/multiguard/panel/dashboard").status_code,200,"Owner dashboard")
    ensure(get("/multiguard/panel/service").status_code,200,"Owner service")
    ensure(get(f"/multiguard/panel/service/{order_a}").status_code,200,"Service detail")
    device_a_response=get(f"/multiguard/panel/device/{install_a}")
    ensure(device_a_response.status_code,200,"Device detail")
    assert f"CI-{str(order_a)[:8]}" in device_a_response.text
    assert f"CI-{str(order_b)[:8]}" not in device_a_response.text, "Cross-device repair leakage"
    ensure(get("/multiguard/panel/versions").status_code,200,"Release list")

    res=get(f"/multiguard/panel/service/{order_a}/media/{media_a}")
    ensure(res.status_code,200,"Authenticated photo")
    assert res.content==photo.read_bytes()
    assert "no-store" in res.headers.get("cache-control","")
    assert res.headers["x-content-type-options"]=="nosniff"
    ensure(get(f"/multiguard/panel/service/{order_b}/media/{media_a}").status_code,404,
           "Media from another service order")
    # The original filename and object key are not leaked into public URLs.
    assert "repairs/device.jpg" not in get(f"/multiguard/panel/service/{order_a}").text

    r=get("/multiguard/panel/dashboard?presence=all&q=Lenovo")
    ensure(r.status_code,200,"Owner device search")
    assert "SAME-SERIAL" in r.text
    ensure(get("/multiguard/panel/dashboard?presence=removed").status_code,200,"Removed filter")

    # OWNER-only settings mutation and anti-CSRF, actually persisted in PostgreSQL.
    settings_page=get("/multiguard/panel/settings")
    csrf=re.search(r'name="csrf_token" value="([^"]+)"',settings_page.text).group(1)
    form={"csrf_token":csrf,"contact_recent_hours":24,"contact_delayed_days":7,
          "no_contact_filter_days":3,"inventory_page_size":20}
    ensure(c.post("/multiguard/panel/settings",data={**form,"csrf_token":"wrong"},
                  auth=auth,follow_redirects=False).status_code,403,"CSRF settings")
    ensure(c.post("/multiguard/panel/settings",data=form,
                  auth=auth,follow_redirects=False).status_code,303,"Save settings")
    assert settings.owner_panel_config()["no_contact_filter_days"]==3

    device_html=get(f"/multiguard/panel/device/{install_a}").text
    note_csrf=re.search(r'<form[^>]+action="/multiguard/panel/device/'+str(install_a)+r'/note"[^>]*>\s*<input[^>]+value="([^"]+)"',device_html).group(1)
    ensure(c.post(f"/multiguard/panel/device/{install_a}/note",
                  data={"priority":"URGENT","note":"Test obserwacji","csrf_token":note_csrf},
                  auth=auth,follow_redirects=False).status_code,303,"Save owner notes")
    assert devices.owner_device_note(install_a)["priority"]=="URGENT"
    assert devices.owner_device_note(install_b)["priority"]=="NORMAL"

    # Prepared diagnostic plans are INACTIVE and have no KeyGate/signed licence.
    plan_html=get(f"/multiguard/panel/device/{install_a}").text
    plan_csrf=re.search(r'<form[^>]+action="/multiguard/panel/device/'+str(install_a)+r'/diagnostic-plan"[^>]*>\s*<input[^>]+value="([^"]+)"',plan_html).group(1)
    ensure(c.post(f"/multiguard/panel/device/{install_a}/diagnostic-plan",
                  data={"action":"prepare","edition":"PRO","days":14,
                        "owner_note":"Usterka sporadyczna","csrf_token":plan_csrf},
                  auth=auth,follow_redirects=False).status_code,303,"Create inactive plan")
    ensure(c.post(f"/multiguard/panel/device/{install_a}/diagnostic-plan",
                  data={"action":"extend","edition":"PRO","days":7,
                        "owner_note":"Test przedłużenia","csrf_token":plan_csrf},
                  auth=auth,follow_redirects=False).status_code,303,"Extend plan")
    with engine.connect() as db:
        plan=db.execute(text("""
          SELECT planned_duration_days,status FROM guard.owner_diagnostic_plans
          WHERE installation_id=:id AND status='PREPARED'
        """),{"id":install_a}).mappings().one()
        link=db.execute(text("""
          SELECT count(*) FROM guard.license_links WHERE service_device_id=:id
        """),{"id":pc_a}).scalar_one()
        edits=db.execute(text("SELECT count(*) FROM guard.owner_diagnostic_plans_audit")).scalar_one()
    assert plan["planned_duration_days"]==21 and plan["status"]=="PREPARED"
    assert link==0 and edits==2
    ensure(get(f"/multiguard/panel/incident/{event_a}").status_code,200,"Event triage screen")
    triage_csrf=re.search(r'name="csrf_token" type="hidden" value="([^"]+)"',
                        get(f"/multiguard/panel/incident/{event_a}").text).group(1)
    ensure(c.post(f"/multiguard/panel/incident/{event_a}",
                  data={"state":"REVIEWING","owner_note":"WHEA checked",
                        "fixed_in_version":"","csrf_token":triage_csrf},
                  auth=auth,follow_redirects=False).status_code,303,"Save event triage")
    with engine.connect() as db:
        state=db.execute(text("""
            SELECT state FROM guard.owner_event_triage WHERE event_id=:id
        """),{"id":event_a}).scalar_one()
        old_event=db.execute(text("SELECT event_type FROM guard.events WHERE event_id=:id"),
                             {"id":event_a}).scalar_one()
    assert state=="REVIEWING" and old_event=="WHEA_LOG"

    # Presence and lifetime: the 'removed' list requires a confirmed signal;
    # the inactive/no-contact view must not invent device failure.
    with engine.begin() as db:
        db.execute(text("""
            INSERT INTO guard.agent_uninstalls(installation_id,event_id)
            VALUES(:iid,:eid)
        """),{"iid":install_b,"eid":uuid.uuid4()})
        db.execute(text("""
            UPDATE guard.installations
            SET last_seen_at=now()-interval '9 days'
            WHERE id=:iid
        """),{"iid":install_a})
    found=get("/multiguard/panel/dashboard?presence=removed")
    ensure(found.status_code,200,"Reported uninstall filtered view")
    assert f"{str(install_b)[:8]}" in found.text
    assert f"{str(install_a)[:8]}" not in found.text
    silent=get("/multiguard/panel/dashboard?presence=silent")
    ensure(silent.status_code,200,"Silent devices filtered view")
    assert f"{str(install_a)[:8]}" in silent.text
    assert f"{str(install_b)[:8]}" not in silent.text

    with engine.begin() as db:
        db.execute(text("""
            UPDATE core.storage_objects SET deleted_at=now()
            WHERE id=:id
        """),{"id":image_storage})
    ensure(get(f"/multiguard/panel/service/{order_a}/media/{media_a}").status_code,
           404,"Deleted private attachment")

    print("PASS: PostgreSQL + actual FastAPI owner routes, private media, device links,")
    print("      CSRF forms, configurable status, audited inactive diagnostic renewals.")
