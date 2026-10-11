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
    order_ready=uuid.uuid4()
    pc_ready=uuid.uuid4()
    waiting_id=uuid.uuid4()
    installed_ready=uuid.uuid4()
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
            INSERT INTO core.devices(id,manufacturer,model,serial_number,
                                     hostname,device_type)
            VALUES (:id,'ASUS','CI-READY','CI-DIFFERENT-SERIAL','ci-host','PC')
        """),{"id":pc_ready})
        db.execute(text("""
            INSERT INTO service.service_orders(
                id,device_id,reception_number,status,received_at,
                intake_description,fault_description)
            VALUES(:id,:did,'CI-READY','READY_FOR_PICKUP',now(),
                'Wydanie testowe','Do odbioru')
        """),{"id":order_ready,"did":pc_ready})
        db.execute(text("""
            INSERT INTO service.owner_finances(
                service_order_id,service_amount,material_cost,donor_material_value)
            VALUES(:id,130,30,15)
        """),{"id":order_ready})
        db.execute(text("""
            INSERT INTO guard.pending_installations(
                installation_id,device_id,discovery_credential_sha256,app_version,
                hostname,manufacturer,model,status)
            VALUES(:id,'ci-await',:hash,'0.3.37','ci-test-pc','ASUS','CI-Model','WAITING')
        """),{"id":waiting_id,"hash":"4"*64})
        db.execute(text("""
            INSERT INTO guard.license_links(
                reception_id,reception_number,service_device_id,
                keygate_license_id,keygate_plan_id,license_key_hash,
                plan_code,duration_months,release_channel,lifecycle,
                installation_id,device_id,credential_sha256,app_version)
            VALUES(:id,'CI-READY',:did,'test-keygate-ready','test-plan',:hash,
                'multi_guard',12,'STABLE','SERVICE_TEST',
                :installed,'ci-device',:cred,'0.3.37')
        """),{"id":order_ready,"did":pc_ready,
               "hash":"2"*64,"installed":installed_ready,"cred":"3"*64})
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

    # Four distinct photos belonging to a single repair: verify indexed
    # carousel navigation, not only the initial thumbnail.
    with engine.begin() as db:
        for slot in range(1, 4):
            extra_store = uuid.uuid4()
            extra_id = uuid.uuid4()
            extra_name = f"device-{slot}.jpg"
            extra_photo = folder / extra_name
            extra_photo.write_bytes(b"\\xff\\xd8\\xff\\xe0" + bytes([slot]) * 16)
            db.execute(text("""
                INSERT INTO core.storage_objects(id,object_key,original_filename,
                                                 mime_type,size_bytes)
                VALUES(:id,:key,:name,'image/jpeg',:size)
            """), {
                "id":extra_store,"key":f"repairs/{extra_name}",
                "name":extra_name,"size":extra_photo.stat().st_size
            })
            db.execute(text("""
                INSERT INTO service.service_order_media(
                    id,service_order_id,storage_object_id,media_kind,caption,sort_order)
                VALUES(:id,:order_id,:sid,'DEVICE_PHOTO',:caption,:order_num)
            """),{
                "id":extra_id,"order_id":order_a,"sid":extra_store,
                "caption":f"Zdjęcie {slot+1}", "order_num":slot
            })

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
    owner_dashboard=get("/multiguard/panel/dashboard")
    ensure(owner_dashboard.status_code,200,"Owner dashboard")
    assert "Szybki dostęp" in owner_dashboard.text
    assert 'href="/multiguard/panel/computers"' in owner_dashboard.text
    assert 'id="devices"' not in owner_dashboard.text, "Dashboard must not duplicate computers table"
    ensure(get("/multiguard/panel/computers",False).status_code,401,"Private inventory")
    inventory_page=get("/multiguard/panel/computers")
    ensure(inventory_page.status_code,200,"Dedicated owner computers")
    assert '<h1>Komputery</h1>' in inventory_page.text
    assert 'id="devices"' in inventory_page.text
    assert "RODZINA MULTI-GUARD V12" not in inventory_page.text
    assert 'class="brand-multi">Multi</span>' in inventory_page.text
    assert 'class="brand-servis">-Servis</span>' in inventory_page.text
    ensure(get("/multiguard/panel/service").status_code,200,"Owner service")
    service_list=get("/multiguard/panel/service").text
    assert 'W trakcie naprawy' in service_list
    assert '/multiguard/panel/service?status=all' in service_list
    assert 'Finanse' not in service_list or 'Finanse zbiorcze' in service_list
    assert get("/multiguard/panel/service?status=bogus").status_code==400
    assert get("/multiguard/panel/service?page_size=999").status_code==400
    stats=get("/multiguard/panel/statistics")
    ensure(stats.status_code,200,"OWNER finances")
    assert "Zysk rzeczywisty" in stats.text
    assert "Zysk ekonomiczny" in stats.text
    assert "Materiał z dawcy" in stats.text
    assert "560,00 zł" in stats.text  # Only two COMPLETED jobs, not READY.
    assert get("/multiguard/panel/statistics",False).status_code==401
    assert get("/multiguard/panel/statistics?period=custom").status_code==200
    assert get("/multiguard/panel/statistics?period=month&month=not-a-month").status_code in (400,422)
    assert get("/multiguard/panel/statistics?period=quarter&quarter=9").status_code==400
    assert 'id="pending"' in inventory_page.text
    assert str(waiting_id).replace("-","")[:8].upper() in inventory_page.text
    assert f'/multiguard/panel/pending/{waiting_id}' in inventory_page.text

    # The actual OWNER inventory HTML shows the full detected value in the
    # edit dialog, while the main table restricts presentation to two lines.
    assert 'class="pending-computers-table"' in inventory_page.text
    assert f'id="pending-name-dialog-{waiting_id}"' in inventory_page.text
    assert f'id="pending-archive-dialog-{waiting_id}"' in inventory_page.text
    assert 'Czy jesteś pewien?' in inventory_page.text
    assert 'TAK, USUŃ Z LISTY' in inventory_page.text
    assert 'class="pending-actions-row"' in inventory_page.text
    assert 'class="pending-archive-trigger"' in inventory_page.text
    assert 'value="ASUS CI-Model"' in inventory_page.text
    assert 'name="return_to" value="computers"' in inventory_page.text
    pending_token=re.search(
        r'name="csrf_token" value="([a-f0-9]{64})"',inventory_page.text
    )
    assert pending_token, "A pending-owner edit form must carry anti-CSRF"
    rename_url=f"/multiguard/panel/installation/{waiting_id}/name"
    desired="Multi-Servis ASUS CI test"
    rename_params={
        "csrf_token":pending_token.group(1),
        "return_to":"computers","friendly_name":desired,
    }
    ensure(c.post(rename_url,data=rename_params).status_code,401,"Only owner may rename")
    ensure(c.post(rename_url,auth=auth,data={**rename_params,"csrf_token":"wrong"}).status_code,
           403,"Rename requires valid CSRF")
    rename=c.post(rename_url,auth=auth,data=rename_params,follow_redirects=False)
    ensure(rename.status_code,303,"OWNER inline pencil editor")
    assert rename.headers["location"]=="/multiguard/panel/computers#pending"
    with engine.connect() as db:
        saved=db.execute(text("""
            SELECT friendly_name FROM guard.owner_installation_labels
            WHERE installation_external_id=:id
        """),{"id":waiting_id}).scalar_one()
        original=db.execute(text("""
            SELECT manufacturer,model FROM guard.pending_installations
            WHERE installation_id=:id
        """),{"id":waiting_id}).one()
    assert saved==desired
    assert tuple(original)==("ASUS","CI-Model"),"Renaming cannot alter hardware metadata"
    renamed_page=get("/multiguard/panel/computers")
    assert f'title="{desired}"' in renamed_page.text
    assert f'value="{desired}"' in renamed_page.text

    # A visible archive button only OPENs confirmation; the separate modal
    # carries the POST. Verify owner and anti-CSRF on the real endpoint,
    # then check one soft-archive audit entry without hard deletion.
    archive_url=f"/multiguard/panel/computers/pending/{waiting_id}/archive"
    ensure(c.post(archive_url,data={"csrf_token":pending_token.group(1)}).status_code,
           401,"Only owner may archive")
    ensure(c.post(archive_url,auth=auth,data={"csrf_token":"bad"}).status_code,
           403,"Archive requires CSRF")
    archived=c.post(archive_url,auth=auth,
                    data={"csrf_token":pending_token.group(1)},follow_redirects=False)
    ensure(archived.status_code,303,"Confirmed owner soft archive")
    with engine.connect() as db:
        status=db.execute(text("""
            SELECT status FROM guard.pending_installations
            WHERE installation_id=:id
        """),{"id":waiting_id}).scalar_one()
        audit_count=db.execute(text("""
            SELECT count(*) FROM guard.pending_archive_events
            WHERE installation_id=:id
        """),{"id":waiting_id}).scalar_one()
    assert status=="ARCHIVED" and audit_count==1
    assert f'/multiguard/panel/pending/{waiting_id}' not in get("/multiguard/panel/computers").text
    ensure(get(f"/multiguard/panel/service/{order_a}").status_code,200,"Service detail")
    d=get(f"/multiguard/panel/service/{order_a}").text
    assert '<details class="card finance-disclosure">' in d, "Financial card must be closed by default"
    assert 'finance-disclosure" open' not in d
    # Web handover is owner-authenticated + CSRF, and commits the service
    # order and the signed licence lifecycle without starting paid time.
    ready=get(f"/multiguard/panel/service/{order_ready}")
    ensure(ready.status_code,200,"Ready service detail")
    assert 'WYDANO SPRZĘT' in ready.text
    token=re.search(r'name="csrf_token" value="([a-f0-9]{64})"',ready.text)
    assert token
    issue_url=f"/multiguard/panel/service/{order_ready}/issue"
    assert c.post(issue_url,data={"csrf_token":token.group(1)}).status_code==401
    assert c.post(issue_url,auth=auth,data={"csrf_token":"wrong"}).status_code==403
    with engine.connect() as db:
        before=db.execute(text("SELECT status FROM service.service_orders WHERE id=:id"),
            {"id":order_ready}).scalar_one()
    assert before=="READY_FOR_PICKUP"
    done=c.post(issue_url,auth=auth,data={"csrf_token":token.group(1)},follow_redirects=False)
    ensure(done.status_code,303,"Authorized release")
    with engine.connect() as db:
        after=db.execute(text("SELECT status FROM service.service_orders WHERE id=:id"),
            {"id":order_ready}).scalar_one()
        lic=db.execute(text("""
            SELECT lifecycle,accepted_at,valid_from,valid_until
            FROM guard.license_links WHERE reception_id=:id
        """),{"id":order_ready}).mappings().one()
    assert after=="COMPLETED"
    assert lic["lifecycle"]=="PENDING_ACCEPTANCE"
    assert not lic["accepted_at"] and not lic["valid_from"] and not lic["valid_until"]
    assert c.post(issue_url,auth=auth,data={"csrf_token":token.group(1)},follow_redirects=False).status_code==303

    device_a_response=get(f"/multiguard/panel/device/{install_a}")
    ensure(device_a_response.status_code,200,"Device detail")
    assert f"CI-{str(order_a)[:8]}" in device_a_response.text
    assert f"CI-{str(order_b)[:8]}" not in device_a_response.text, "Cross-device repair leakage"
    ensure(get("/multiguard/panel/versions").status_code,200,"Release list")

    detail=get(f"/multiguard/panel/service/{order_a}").text
    assert '<dialog class="photo-viewer"' in detail
    assert 'class="gallery-open gallery-thumb-link"' in detail
    assert 'data-gallery-index="0"' in detail
    assert 'data-gallery-index="1"' in detail
    assert 'data-gallery-index="2"' in detail
    assert 'data-gallery-index="3"' in detail
    assert detail.count('class="gallery-open gallery-thumb-link"') == 4
    assert 'Zdjęcia i dokumenty (4)' in detail
    assert 'viewer-next' in detail and 'viewer-prev' in detail
    assert "ArrowRight" in detail and "touchend" in detail and "viewer-zoom-in" in detail

    res=get(f"/multiguard/panel/service/{order_a}/media/{media_a}")
    ensure(res.status_code,200,"Authenticated photo")
    assert res.content==photo.read_bytes()
    assert "no-store" in res.headers.get("cache-control","")
    assert res.headers["x-content-type-options"]=="nosniff"
    ensure(get(f"/multiguard/panel/service/{order_b}/media/{media_a}").status_code,404,
           "Media from another service order")
    # The original filename and object key are not leaked into public URLs.
    assert "repairs/device.jpg" not in get(f"/multiguard/panel/service/{order_a}").text

    r=get("/multiguard/panel/computers?presence=all&q=Lenovo")
    ensure(r.status_code,200,"Owner device search")
    assert "SAME-SERIAL" in r.text
    ensure(get("/multiguard/panel/computers?presence=removed").status_code,200,"Removed filter")

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
    found=get("/multiguard/panel/computers?presence=removed")
    ensure(found.status_code,200,"Reported uninstall filtered view")
    assert f'href="/multiguard/panel/device/{install_b}"' in found.text
    assert f'href="/multiguard/panel/device/{install_a}"' not in found.text
    silent=get("/multiguard/panel/computers?presence=silent")
    ensure(silent.status_code,200,"Silent devices filtered view")
    assert f'href="/multiguard/panel/device/{install_a}"' in silent.text
    assert f'href="/multiguard/panel/device/{install_b}"' not in silent.text

    with engine.begin() as db:
        db.execute(text("""
            UPDATE core.storage_objects SET deleted_at=now()
            WHERE id=:id
        """),{"id":image_storage})
    ensure(get(f"/multiguard/panel/service/{order_a}/media/{media_a}").status_code,
           404,"Deleted private attachment")


    # OWNER-only unified service mode: two client forms, one two-click
    # consent guard; no standalone workshop form and monitoring OFF by default.
    import base64 as _b64, hashlib as _hash, json as _json
    os.environ["MULTIGUARD_SIGNING_SEED_B64"]=_b64.b64encode(b"1"*32).decode()
    mode_direct=uuid.uuid4()
    mode_order=uuid.uuid4()
    mode_order_id=uuid.uuid4()
    mode_secret="ci-mode-discovery-secret-123456789"
    with engine.begin() as db:
        for iid,dev in ((mode_direct,"ci-mode-direct-device"),
                        (mode_order,"ci-mode-order-device")):
            db.execute(text("""
                INSERT INTO guard.pending_installations(
                  installation_id,device_id,discovery_credential_sha256,
                  app_version,hostname,manufacturer,model,status)
                VALUES(:iid,:dev,:cred,'0.3.39','ci-mode',
                       'Lenovo','CI-Mode','WAITING')
            """),{"iid":iid,"dev":dev,
                  "cred":_hash.sha256(mode_secret.encode()).hexdigest()})
        db.execute(text("""
            INSERT INTO service.service_orders(id,device_id,
                reception_number,status,received_at)
            VALUES(:id,:dev,'CI-2026-01234','IN_PROGRESS',now())
        """),{"id":mode_order_id,"dev":pc_a})
    mode_page=get(f"/multiguard/panel/pending/{mode_direct}")
    ensure(mode_page.status_code,200,"Unified OWNER computer form")
    assert mode_page.text.count('value="SERVICE"')==2
    assert 'Tryb warsztatowy' not in mode_page.text
    assert 'id="workshop-mode"' not in mode_page.text
    assert 'data-service-approve' in mode_page.text
    suggest="/multiguard/panel/service-orders/suggest?q=123"
    ensure(get(suggest,False).status_code,401,"Owner-only order autocomplete")
    assert any(r["number"]=="CI-2026-01234"
               for r in get(suggest).json()["results"])
    assert get("/multiguard/panel/service-orders/suggest?q=12").json()["results"]==[]

    token=license._workshop_csrf()
    form={"edition":"PRO","months":"SERVICE","release_channel":"STABLE",
          "service_confirm":"CONFIRM_WORKSHOP","csrf_token":token}
    direct_url=f"/multiguard/panel/pending/{mode_direct}/direct"
    ensure(c.post(direct_url,data=form).status_code,401,"Service OWNER Basic")
    ensure(c.post(direct_url,auth=auth,
                  data={**form,"csrf_token":"bad"}).status_code,403,"Service CSRF")
    ensure(c.post(direct_url,auth=auth,
                  data={**form,"service_confirm":""}).status_code,400,
           "Require deliberate second click")
    with engine.connect() as db:
        assert db.execute(text("""
          SELECT count(*) FROM guard.workshop_grants WHERE installation_id=:id
        """),{"id":mode_direct}).scalar_one()==0
    ensure(c.post(direct_url,auth=auth,data=form,
                  follow_redirects=False).status_code,303,"Service enabled")
    with engine.connect() as db:
        grant=db.execute(text("""
          SELECT enabled,monitoring_profile,associated_reception_id
          FROM guard.workshop_grants WHERE installation_id=:id
        """),{"id":mode_direct}).mappings().one()
    assert grant["enabled"] is True and grant["monitoring_profile"]=="OFF"
    assert grant["associated_reception_id"] is None
    owner_modes=get("/multiguard/panel")
    ensure(owner_modes.status_code,200,"OWNER central service management")
    assert 'data-owner-monitor-toggle' in owner_modes.text
    assert f'/multiguard/panel/workshop/{mode_direct}/disable' in owner_modes.text

    discovery={"installationId":str(mode_direct),
               "deviceId":"ci-mode-direct-device",
               "discoveryCredential":mode_secret}
    server_lease=c.post("/v1/multi-guard/discovery/assignment",json=discovery)
    ensure(server_lease.status_code,200,"Signed service grant")
    assert server_lease.json()["workshopMonitoring"]=={
        "enabled":False,"profile":"OFF"}
    envelope=server_lease.json()["workshopLease"]
    assert _json.loads(envelope["payload"])["lifecycle"]=="WORKSHOP"
    license._signing_key().public_key().verify(
        _b64.b64decode(envelope["signatureB64"]),envelope["payload"].encode())

    monitor_url=f"/multiguard/panel/workshop/{mode_direct}/monitoring"
    ensure(c.post(monitor_url,auth=auth,
          data={"csrf_token":"bad","monitoring_enabled":"yes",
                "profile":"OBSERVATION"}).status_code,403,"Monitoring CSRF")
    ensure(c.post(monitor_url,auth=auth,
          data={"csrf_token":token,"monitoring_enabled":"yes",
                "profile":"BAD"}).status_code,400,"Monitoring whitelisted profiles")
    ensure(c.post(monitor_url,auth=auth,
          data={"csrf_token":token,"monitoring_enabled":"yes",
                "profile":"OBSERVATION"},
          follow_redirects=False).status_code,303,"Monitoring opt in")
    observed=c.post("/v1/multi-guard/discovery/assignment",json=discovery)
    assert observed.json()["workshopMonitoring"]=={
        "enabled":True,"profile":"OBSERVATION"}
    sample={"capturedAt":"2026-10-10T20:00:00Z","cpuLoadPercent":42.0,
            "cpuTemperatureC":56.0,"ramUsedPercent":24.0,
            "gpuLoadPercent":None,"gpuTemperatureC":None}
    report={"installationId":str(mode_direct),
            "deviceId":"ci-mode-direct-device",
            "discoveryCredential":mode_secret,
            "summary":{"monitoringProfile":"OBSERVATION","samples":[sample]}}
    ensure(c.post("/v1/multi-guard/workshop/report",json=report).status_code,
           200,"Extended service report")
    history=get(f"/multiguard/panel/workshop/{mode_direct}/reports")
    ensure(history.status_code,200,"Private report history")
    assert 'OBSERVATION' in history.text and '42.0%' in history.text
    ensure(c.post(monitor_url,auth=auth,
          data={"csrf_token":token,"profile":"STANDARD"},
          follow_redirects=False).status_code,303,"Disable monitoring only")
    with engine.connect() as db:
        assert db.execute(text("""
          SELECT monitoring_profile FROM guard.workshop_grants WHERE installation_id=:id
        """),{"id":mode_direct}).scalar_one()=="OFF"
    assert c.post("/v1/multi-guard/workshop/report",json=report).status_code==409

    revoke_url=f"/multiguard/panel/workshop/{mode_direct}/disable"
    ensure(c.post(revoke_url,auth=auth,
          data={"csrf_token":token,"confirmation":"NO"}).status_code,400,
          "Second confirmation needed to revoke")
    ensure(c.post(revoke_url,auth=auth,
          data={"csrf_token":token,"confirmation":"CONFIRM_DISABLE"},
          follow_redirects=False).status_code,303,"OWNER revoked service")
    revoked=c.post("/v1/multi-guard/discovery/assignment",json=discovery)
    ensure(revoked.status_code,200,"Client checks revoked state")
    unsigned=revoked.json()["workshopLease"]
    assert _json.loads(unsigned["payload"])["lifecycle"]=="UNKNOWN"
    license._signing_key().public_key().verify(
        _b64.b64decode(unsigned["signatureB64"]),unsigned["payload"].encode())
    assert revoked.json()["workshopMonitoring"]=={
        "enabled":False,"profile":"OFF"}
    with engine.connect() as db:
        assert db.execute(text("""
          SELECT status FROM guard.pending_installations WHERE installation_id=:id
        """),{"id":mode_direct}).scalar_one()=="WAITING"
    assert c.post("/v1/multi-guard/workshop/report",json=report).status_code==403

    # Also verify the service-order path doesn't create paid KeyGate rights.
    order_form={"reception_number":"CI-2026-01234","edition":"STANDARD",
                "months":"SERVICE","release_channel":"STABLE",
                "csrf_token":token,"service_confirm":"CONFIRM_WORKSHOP"}
    order_url=f"/multiguard/panel/pending/{mode_order}/assign"
    ensure(c.post(order_url,auth=auth,
          data={**order_form,"service_confirm":""}).status_code,400,
           "Order mode requires explicit confirmation")
    ensure(c.post(order_url,auth=auth,data=order_form,
          follow_redirects=False).status_code,303,"Service mode linked to order")
    with engine.connect() as db:
        association=db.execute(text("""
            SELECT associated_reception_id,monitoring_profile,enabled
            FROM guard.workshop_grants WHERE installation_id=:id
        """),{"id":mode_order}).mappings().one()
    assert association["associated_reception_id"]==mode_order_id
    assert association["monitoring_profile"]=="OFF" and association["enabled"]
    print("PASS: unified OWNER service flow, signed revocation, monitoring OFF/ON, reports, order autocomplete.")

    # A true direct sale must never insert a repair order. KeyGate is
    # mocked locally, while SQL and FastAPI routes run against real Postgres.
    import base64, hashlib, json
    direct_id=uuid.uuid4()
    direct_device="ci-direct-device-id-1234567890"
    discovery_secret="ci-workshop-secret-1234567890-abcdefgh"
    token_key="KG-AAAAAAAA-AAAAAAAA-AAAAAAAA-AAAAAAAA"
    with engine.begin() as db:
        db.execute(text("""
            INSERT INTO guard.pending_installations(
                installation_id,device_id,discovery_credential_sha256,
                app_version,hostname,manufacturer,model,status
            ) VALUES(:id,:device,:cred,'0.3.37','ci-direct-host',
                     'ASUS','Client-DIRECT','WAITING')
        """), {"id":direct_id,"device":direct_device,
               "cred":hashlib.sha256(discovery_secret.encode()).hexdigest()})
    os.environ["MULTIGUARD_SIGNING_SEED_B64"]=base64.b64encode(b"1"*32).decode()
    docs=[{"kind":name,"version":"v1","title":name,"content_markdown":"Treść "+name}
          for name in ("terms","privacy","safety")]
    os.environ["MULTIGUARD_REQUIRED_DOCUMENTS"]=json.dumps(docs)
    mock_calls={"create":0,"keygate_end":[]}
    def fake_create_license(*,reception_number,edition,months):
        mock_calls["create"]+=1
        assert reception_number.startswith("MG-DIRECT-")
        assert edition=="PRO" and months==12
        return {"id":"fake-direct-ci","_plan_id":"fake-plan",
                "_license_key":token_key}
    license._keygate_create_license=fake_create_license
    license._keygate_reveal=lambda license_id:token_key
    license._keygate_activate=lambda key,device,installation:{"license_id":"fake-direct-ci"}
    license._keygate_license=lambda license_id:{"status":"active"}
    license._keygate_set_valid_until=lambda license_id,end:mock_calls["keygate_end"].append(end)

    # Workshop rights exist before sale, with a signed envelope.
    workshop=license._set_workshop_grant(direct_id,"PRO","STABLE",True)
    assert workshop["edition"]=="PRO" and workshop["enabled"]
    discovery={"installationId":str(direct_id),"deviceId":direct_device,
               "discoveryCredential":discovery_secret}
    lease=c.post("/v1/multi-guard/discovery/assignment",json=discovery)
    ensure(lease.status_code,200,"Initial workshop lease")
    assert json.loads(lease.json()["workshopLease"]["payload"])["lifecycle"]=="WORKSHOP"
    assert lease.json()["assigned"] is False

    direct_url=f"/multiguard/pending-installations/{direct_id}/direct"
    ensure(c.post(direct_url,json={"edition":"PRO","months":12}).status_code,
           200,"Direct licence without service reception")
    assert c.post(direct_url,json={"edition":"PRO","months":12}).status_code==409
    with engine.connect() as db:
        assert db.execute(text("""
            SELECT count(*) FROM service.service_orders
            WHERE reception_number LIKE 'MG-DIRECT-%'
        """)).scalar_one()==0
        linked=db.execute(text("""
            SELECT reception_id,service_device_id,installation_id,sale_kind
            FROM guard.license_links WHERE keygate_license_id='fake-direct-ci'
        """)).mappings().one()
    assert linked["reception_id"] is None
    assert linked["service_device_id"] is None
    assert linked["installation_id"]==direct_id
    assert linked["sale_kind"]=="DIRECT"
    assert mock_calls["create"]==1

    before_handover=c.post("/v1/multi-guard/discovery/assignment",json=discovery)
    ensure(before_handover.status_code,200,"Direct assignment online")
    assert before_handover.json()["assigned"] is True
    assert before_handover.json()["provisioningToken"]==token_key
    direct_hand=f"/multiguard/pending-installations/{direct_id}/handover"
    ensure(c.post(direct_hand).status_code,200,"Direct handover without service")
    assert c.post(direct_hand).status_code==200

    provision_json={"requestId":str(uuid.uuid4()),"nonce":"ci-nonce",
      "sentAt":"2026-10-09T00:00:00Z","provisioningToken":token_key,
      "installationId":str(direct_id),"deviceId":direct_device,"appVersion":"0.3.37"}
    provision_result=c.post("/v1/multi-guard/provision",json=provision_json)
    ensure(provision_result.status_code,200,"Direct provisioning after handover")
    signed=json.loads(provision_result.json()["signedLicense"]["payload"])
    assert signed["lifecycle"]=="PENDING_ACCEPTANCE",signed
    assert signed["validUntil"] is None
    assert len(provision_result.json()["requiredDocuments"])==3
    assert not mock_calls["keygate_end"],"Paid period must not start before consent"

    refresh_fields={
      "requestId":str(uuid.uuid4()),"nonce":"ci-nonce",
      "sentAt":"2026-10-09T00:00:00Z",
      "installationId":str(direct_id),"deviceId":direct_device,
      "installationCredential":provision_result.json()["installationCredential"],
      "appVersion":"0.3.37"}
    accept_docs=[{"kind":d["kind"],"version":d["version"],
                  "sha256":hashlib.sha256(d["content_markdown"].encode()).hexdigest()}
                 for d in docs]
    accepted=c.post("/v1/multi-guard/acceptance",
                    json={**refresh_fields,"documents":accept_docs})
    ensure(accepted.status_code,200,"Direct client activation after three documents")
    final=json.loads(accepted.json()["signedLicense"]["payload"])
    assert final["lifecycle"]=="ACTIVE" and final["validUntil"]
    assert len(mock_calls["keygate_end"])==1
    direct_link=license._link_by_installation(direct_id)
    assert direct_link["valid_from"] is not None
    assert direct_link["accepted_at"] is not None

    # Strict idempotent renewal. Two clicks with the same ID must not
    # add two years; the beginning of the term never changes.
    renewal_id=str(uuid.uuid4())
    extend_url=f"/multiguard/licenses/installations/{direct_id}/extend"
    payload={"operationId":renewal_id,"months":12,"paymentConfirmed":True}
    renewed=c.post(extend_url,json=payload)
    ensure(renewed.status_code,200,"Direct paid renewal")
    assert renewed.json()["status"]=="EXTENDED"
    again=c.post(extend_url,json=payload)
    ensure(again.status_code,200,"Idempotent renewal")
    assert again.json()["status"]=="ALREADY_EXTENDED"
    assert renewed.json()["newValidUntil"]==again.json()["newValidUntil"]
    assert renewed.json()["oldValidUntil"]==final["validUntil"]
    with engine.connect() as db:
        assert db.execute(text("""
            SELECT count(*) FROM guard.license_extensions
            WHERE keygate_license_id='fake-direct-ci'
        """)).scalar_one()==1
    assert len(mock_calls["keygate_end"])==2

    # Gate future deployment on read-only compatibility with the historical
    # Multi-Servis schema. It must neither mutate nor fetch customer records.
    spec=importlib.util.spec_from_file_location(
        "owner_preflight",
        str(ROOT/"scripts"/"preflight_owner_panel.py"),
    )
    preflight=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    contract=preflight.contract_check(engine,media_root)
    assert contract["result"]=="PASS",contract
    assert contract["database_mutated"] is False
    assert contract["production_data_accessed"] is False
    # Owner privacy and accounting-period regression: September must not
    # appear in an October report merely because PostgreSQL weeks start on
    # Monday 28 September. October sums must contain BOTH revenue and costs
    # only for orders marked COMPLETED, using the handover timestamp.
    from datetime import datetime as _dt
    from zoneinfo import ZoneInfo as _ZoneInfo
    _waw = _ZoneInfo("Europe/Warsaw")
    fixture_rows = [
        ("SEP", "2030-09-28T10:00:00+02:00", "COMPLETED", 940, 333),
        ("OCT", "2030-10-01T11:00:00+02:00", "COMPLETED", 270, 70),
        ("READY", "2030-10-02T09:00:00+02:00", "READY_FOR_PICKUP", 9999, 9999),
        ("NOV", "2030-11-01T10:00:00+01:00", "COMPLETED", 500, 100),
    ]
    with engine.begin() as db:
        for tag,issued_time,st,amount,cost in fixture_rows:
            order_id = uuid.uuid4()
            db.execute(text("""
                INSERT INTO service.service_orders (
                    id,device_id,reception_number,status,received_at,completed_at
                ) VALUES (:id,:device_id,:number,:status,:received,:completed)
            """), {
                "id":order_id,"device_id":pc_a,
                "number":"STAT-"+tag+"-"+str(order_id)[:8],"status":st,
                "received":_dt(2030,9,15,tzinfo=_waw),
                "completed":_dt.fromisoformat(issued_time) if st=="COMPLETED" else None,
            })
            db.execute(text("""
                INSERT INTO service.owner_finances (
                    service_order_id,service_amount,material_cost,donor_material_value
                ) VALUES (:id,:revenue,:cost,0)
            """),{"id":order_id,"revenue":amount,"cost":cost})
    oct_html = get("/multiguard/panel/statistics?period=month&month=2030-10")
    ensure(oct_html.status_code,200,"October 2030 month handover")
    assert 'Finanse wybranego okresu' in oct_html.text
    assert '<details class="card statistics-finance-disclosure"' in oct_html.text
    assert '<details class="card statistics-finance-disclosure" open' not in oct_html.text
    # The number of issued orders is visible while all financial figures
    # belong to a closed element (not painted until OWNER expands it).
    assert 'Wydane zlecenia</b><strong>1</strong>' in oct_html.text
    money_section = oct_html.text.split('<details class="card statistics-finance-disclosure"',1)[1]
    outside = oct_html.text.split('<details class="card statistics-finance-disclosure"',1)[0]
    assert "270,00 zł" in money_section and "70,00 zł" in money_section
    assert "270,00 zł" not in outside and "70,00 zł" not in outside
    assert "940,00 zł" not in oct_html.text and "333,00 zł" not in oct_html.text
    assert "9999,00 zł" not in oct_html.text and "500,00 zł" not in oct_html.text
    assert "01.10.2030" in money_section
    assert "28.09.2030" not in money_section
    assert "28.09" not in money_section, "No September labels in October report"
    print("PASS: month=October uses Warsaw handover day and excludes September/READY/November.")
    print("PASS: OWNER's financial sums, costs and trend are collapsed by default.")

    print("PASS: read-only owner-panel schema and media-root preflight.")
    print("PASS: PostgreSQL + actual FastAPI owner routes, private media, device links,")
    print("      CSRF forms, configurable status, audited inactive diagnostic renewals.")
