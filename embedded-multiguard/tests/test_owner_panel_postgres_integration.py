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
            """CREATE TABLE IF NOT EXISTS service.service_order_notes(
                id UUID PRIMARY KEY,service_order_id UUID REFERENCES service.service_orders(id),
                note_text TEXT NOT NULL,visibility TEXT NOT NULL DEFAULT 'STAFF',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),deleted_at TIMESTAMPTZ)""",
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
    workshop=importlib.import_module("app.routers.multiguard_workshop_remote")
    service=importlib.import_module("app.routers.multiguard_service_panel")
    settings=importlib.import_module("app.routers.multiguard_panel_settings")
    devices=importlib.import_module("app.routers.multiguard_panel_devices")
    triage=importlib.import_module("app.routers.multiguard_panel_triage")
    diagnostic=importlib.import_module("app.routers.multiguard_panel_diagnostics")

    # Real SQL initializers run against fresh ephemeral PostgreSQL.
    license._ensure_schema()
    runtime._ensure_schema()
    workshop._schema()
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
        # Native Android note history is a different table from the
        # service_orders.technician_notes/customer_notes legacy fields.
        for rank,(id,order,content,visibility,deleted) in enumerate([
            (uuid.uuid4(),order_a,"Pierwsza notatka: problem z BIOS","STAFF",None),
            (uuid.uuid4(),order_a,"Druga notatka z Androida: sprawdź RAM <script>alert(1)</script>","OWNER_ONLY",None),
            (uuid.uuid4(),order_a,"Ukryta notatka po usunięciu","STAFF","2025-10-10 12:00:00+00"),
            (uuid.uuid4(),order_b,"TAJNA_INNEGO_ZLECENIA","OWNER_ONLY",None),
        ]):
            db.execute(text("""
                INSERT INTO service.service_order_notes(
                    id,service_order_id,note_text,visibility,deleted_at,created_at
                ) VALUES(:id,:order_id,:note,:visibility,:deleted_at,
                          now() + (:rank * interval '1 second'))
            """),{"id":id,"order_id":order,"note":content,"rank":rank,
                   "visibility":visibility,"deleted_at":deleted})
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
    for mod in (license,runtime,workshop,service,settings,devices,triage,diagnostic):
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
    assert not re.search(r'<[^>]+class="[^"]*\bhub-tile\b', owner_dashboard.text)
    assert "Szybkie działania" not in owner_dashboard.text
    assert "/multiguard/panel/licenses#pending" in owner_dashboard.text
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
    assert 'id="pending"' not in inventory_page.text
    assert f'/multiguard/panel/pending/{waiting_id}' not in inventory_page.text
    ensure(get("/multiguard/panel/licenses",False).status_code,401,"Private licence queue")
    license_page=get("/multiguard/panel/licenses")
    ensure(license_page.status_code,200,"Licence queue")
    assert 'id="assigned"' in license_page.text
    # Optional local browser fixtures contain only this test's synthetic data.
    if os.environ.get("OWNER_TEST_HTML_DIR"):
        output = Path(os.environ["OWNER_TEST_HTML_DIR"])
        output.mkdir(parents=True, exist_ok=True)
        for name, response in (("licenses", license_page), ("computers", inventory_page),
                               ("dashboard", owner_dashboard)):
            (output / (name + ".html")).write_text(response.text, encoding="utf-8")
    assert 'id="pending"' in license_page.text
    assert str(waiting_id).replace("-","")[:8].upper() in license_page.text
    assert f'/multiguard/panel/pending/{waiting_id}' in license_page.text

    # The actual OWNER inventory HTML shows the full detected value in the
    # edit dialog, while the main table restricts presentation to two lines.
    assert 'class="pending-computers-table"' in license_page.text
    assert f'id="pending-name-dialog-{waiting_id}"' in license_page.text
    assert f'id="pending-archive-dialog-{waiting_id}"' in license_page.text
    assert 'Czy jesteś pewien?' in license_page.text
    assert 'TAK, USUŃ Z LISTY' in license_page.text
    assert 'class="pending-actions-row"' in license_page.text
    assert 'class="pending-archive-trigger"' in license_page.text
    assert 'value="ASUS CI-Model"' in license_page.text
    assert 'name="return_to" value="licenses"' in license_page.text
    pending_token=re.search(
        r'name="csrf_token" value="([a-f0-9]{64})"',license_page.text
    )
    assert pending_token, "A pending-owner edit form must carry anti-CSRF"
    rename_url=f"/multiguard/panel/installation/{waiting_id}/name"
    desired="Multi-Servis ASUS CI test"
    rename_params={
        "csrf_token":pending_token.group(1),
        "return_to":"licenses","friendly_name":desired,
    }
    ensure(c.post(rename_url,data=rename_params).status_code,401,"Only owner may rename")
    ensure(c.post(rename_url,auth=auth,data={**rename_params,"csrf_token":"wrong"}).status_code,
           403,"Rename requires valid CSRF")
    rename=c.post(rename_url,auth=auth,data=rename_params,follow_redirects=False)
    ensure(rename.status_code,303,"OWNER inline pencil editor")
    assert rename.headers["location"]=="/multiguard/panel/licenses#pending"
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
    renamed_page=get("/multiguard/panel/licenses")
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
    assert f'/multiguard/panel/pending/{waiting_id}' not in get("/multiguard/panel/licenses").text
    ensure(get(f"/multiguard/panel/service/{order_a}").status_code,200,"Service detail")
    d=get(f"/multiguard/panel/service/{order_a}").text
    assert "Notatki do zlecenia (2)" in d
    assert "Pierwsza notatka: problem z BIOS" in d
    assert "Druga notatka z Androida" in d
    assert "&lt;script&gt;" in d and "<script>alert(1)</script>" not in d
    assert "Tylko właściciel" in d
    assert "Ukryta notatka po usunięciu" not in d
    assert "TAJNA_INNEGO_ZLECENIA" not in d
    all_page=get("/multiguard/panel/service?status=all").text
    assert "Ostatnia notatka" in all_page and "Druga notatka z Androida" in all_page
    assert get("/multiguard/panel/service?q=problem%20z%20BIOS&status=all").status_code==200
    lookup=get("/multiguard/panel/service?q=problem%20z%20BIOS&status=all").text
    assert f'CI-{str(order_a)[:8]}' in lookup and f'CI-{str(order_b)[:8]}' not in lookup
    assert get(f"/multiguard/panel/service/{order_a}",False).status_code==401
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
    assert mode_page.text.count('value="NONE"')==2
    assert "POZOSTAW BEZ LICENCJI" in mode_page.text
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
    order_url=f"/multiguard/panel/pending/{mode_order}/assign"
    no_license={"edition":"STANDARD","months":"NONE","release_channel":"STABLE",
                "csrf_token":token}
    ensure(c.post(direct_url,data=no_license).status_code,401,"No licence OWNER Basic")
    ensure(c.post(direct_url,auth=auth,
                  data={**no_license,"csrf_token":"bad"}).status_code,403,
           "No licence requires CSRF")
    for url in (direct_url,order_url):
        response=c.post(url,auth=auth,data=no_license,follow_redirects=False)
        ensure(response.status_code,303,"Explicit no-licence selection")
        assert response.headers["location"]=="/multiguard/panel/licenses#pending"
    with engine.connect() as db:
        for iid in (mode_direct,mode_order):
            assert db.execute(text("""
              SELECT status FROM guard.pending_installations
              WHERE installation_id=:iid
            """),{"iid":iid}).scalar_one()=="WAITING"
            assert db.execute(text("""
              SELECT count(*) FROM guard.license_links WHERE installation_id=:iid
            """),{"iid":iid}).scalar_one()==0
            assert db.execute(text("""
              SELECT count(*) FROM guard.workshop_grants
              WHERE installation_id=:iid AND enabled=TRUE
            """),{"iid":iid}).scalar_one()==0
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
    queue_html=get("/multiguard/panel/licenses").text
    assert f'/multiguard/panel/pending/{mode_direct}' not in queue_html
    assert f'/multiguard/panel/pending/{mode_order}' in queue_html
    owner_modes=get("/multiguard/panel/service-mode")
    ensure(owner_modes.status_code,200,"OWNER central service management")
    assert 'data-owner-monitor-toggle' in owner_modes.text
    assert 'class="owner-service-row"' in owner_modes.text
    assert f'/multiguard/panel/workshop/{mode_direct}/edition' in owner_modes.text
    assert f'/multiguard/panel/workshop/{mode_direct}/disable' in owner_modes.text
    # Existing service grant must have its own edition controls. Neither
    # the KeyGate creation form nor the prior uncertain-create warning may
    # masquerade as a Standard->Pro service edition change.
    assigned_device=get(f"/multiguard/panel/pending/{mode_direct}")
    assert 'ZMIEŃ WARIANT SERWISOWY STANDARD / PRO' in assigned_device.text
    assert f'action="/multiguard/panel/pending/{mode_direct}/direct"' not in assigned_device.text
    edition_url=f"/multiguard/panel/workshop/{mode_direct}/edition"
    ensure(c.post(edition_url,auth=auth,data={
        "edition":"STANDARD","csrf_token":"bad"}).status_code,403,"Service edition CSRF")
    ensure(c.post(edition_url,auth=auth,data={
        "edition":"PREMIUM","csrf_token":token}).status_code,400,"Service edition validation")
    ensure(c.post(edition_url,auth=auth,data={
        "edition":"STANDARD","csrf_token":token},follow_redirects=False).status_code,
        303,"Switch indefinite service Pro to Standard without KeyGate")
    std_lease=c.post("/v1/multi-guard/discovery/assignment",json={
        "installationId":str(mode_direct),"deviceId":"ci-mode-direct-device",
        "discoveryCredential":mode_secret})
    assert std_lease.status_code==200
    assert _json.loads(std_lease.json()["workshopLease"]["payload"])["planCode"]=="multi_guard"
    ensure(c.post(edition_url,auth=auth,data={
        "edition":"PRO","csrf_token":token},follow_redirects=False).status_code,
        303,"Restore indefinite service Pro without new KeyGate license")
    with engine.connect() as db:
        service_state=db.execute(text("""
            SELECT edition,monitoring_profile,enabled
            FROM guard.workshop_grants WHERE installation_id=:id
        """),{"id":mode_direct}).mappings().one()
        service_audit=db.execute(text("""
            SELECT count(*) FROM guard.workshop_grant_audit
            WHERE installation_id=:id
        """),{"id":mode_direct}).scalar_one()
        keygate_links=db.execute(text("""
            SELECT count(*) FROM guard.license_links WHERE installation_id=:id
        """),{"id":mode_direct}).scalar_one()
    assert service_state["edition"]=="PRO" and service_state["monitoring_profile"]=="OFF"
    assert service_state["enabled"] and service_audit>=3 and keygate_links==0
    # 0.3.42 WORKSHOP PRO: registered discovery identity, consent, and
    # independent MeshCentral share. It never creates a KeyGate licence.
    from datetime import datetime as _workshop_time, timezone as _workshop_tz
    def workshop_body():
        return {
            "requestId":str(uuid.uuid4()),"nonce":str(uuid.uuid4()),
            "sentAt":_workshop_time.now(_workshop_tz.utc).isoformat(),
            "installationId":str(mode_direct),
            "deviceId":"ci-mode-direct-device",
            "discoveryCredential":mode_secret,
        }
    owned=get('/multiguard/panel/remote?q=CI-Mode')
    ensure(owned.status_code,200,"Remote searchable workshop PRO")
    assert f'selected={mode_direct}' in owned.text
    assert 'SERWIS · PRO' in owned.text
    assert 'Wyszukaj po nazwie, modelu, ID lub numerze zlecenia' in owned.text
    assert 'CI-Mode' in owned.text
    before_node=get(f'/multiguard/panel/remote?selected={mode_direct}')
    ensure(before_node.status_code,200,"Workshop inventory without technical node")
    assert 'Połączenie nie jest jeszcze dostępne' in before_node.text
    assert 'POWIĄŻ MESH' not in before_node.text
    assert 'name="mesh_node_id"' not in before_node.text
    assert get('/multiguard/panel/remote?q=CI-Mode',False).status_code==401
    invalid_credential={**workshop_body(),"discoveryCredential":"wrong-but-long-enough-123456789012345"}
    ensure(c.post('/multiguard/agent/workshop/remote/poll',
                  json=invalid_credential).status_code,401,"Workshop discovery required")
    expired_credential={**workshop_body(),"sentAt":"2020-01-01T00:00:00Z"}
    ensure(c.post('/multiguard/agent/workshop/remote/poll',
                  json=expired_credential).status_code,401,"Workshop expired request refused")
    ensure(c.post('/multiguard/agent/workshop/remote/poll',
                  json=workshop_body()).status_code,200,"Workshop agent poll")
    node_url=f"/multiguard/panel/remote/workshop/{mode_direct}/mesh-bind"
    ensure(c.post(node_url,auth=auth,
                  data={"csrf_token":"bad","mesh_node_id":"node/ci-mode-direct"},
                  follow_redirects=False).status_code,403,"Mesh bind needs CSRF")
    ensure(c.post(node_url,auth=auth,
                  data={"csrf_token":token,"mesh_node_id":"node/ci-mode-direct"},
                  follow_redirects=False).status_code,303,"Bind synthetic workshop node")
    one_click=get(f'/multiguard/panel/remote?selected={mode_direct}')
    ensure(one_click.status_code,200,"OWNER one click ready after agent bind")
    assert 'POŁĄCZ</button>' in one_click.text
    assert 'POWIĄŻ MESH' not in one_click.text
    owner_request=f"/multiguard/panel/remote/workshop/{mode_direct}/request"
    ensure(c.post(owner_request,auth=auth,
                  data={"csrf_token":token},follow_redirects=False).status_code,
           303,"Owner can request workshop session without support ticket")
    polled=c.post('/multiguard/agent/workshop/remote/poll',json=workshop_body())
    ensure(polled.status_code,200,"Beta client poll receives workshop session")
    sid=polled.json()["session"]["sessionId"]
    assert polled.json()["session"]["status"]=="REQUESTED"
    assert polled.json()["session"]["supportRequestId"]==sid
    waiting=get(f'/multiguard/panel/remote?selected={mode_direct}')
    assert 'setTimeout(function(){window.location.reload()},2500)' in waiting.text
    denied=c.post('/multiguard/agent/workshop/remote/decision',json={
        **workshop_body(),"sessionId":sid,"allowDesktop":False,"allowFiles":False
    })
    ensure(denied.status_code,200,"Client explicit session denial")
    assert denied.json()["session"]["status"]=="DENIED"
    ensure(c.post(owner_request,auth=auth,data={"csrf_token":token},
                  follow_redirects=False).status_code,303,"Fresh request after refusal")
    polled=c.post('/multiguard/agent/workshop/remote/poll',json=workshop_body())
    sid=polled.json()["session"]["sessionId"]
    allowed=c.post('/multiguard/agent/workshop/remote/decision',json={
        **workshop_body(),"sessionId":sid,"allowDesktop":True,"allowFiles":False
    })
    ensure(allowed.status_code,200,"Client consents to desktop")
    assert allowed.json()["session"]["status"]=="CONSENTED"
    ready_page=get(f'/multiguard/panel/remote?selected={mode_direct}')
    assert 'owner-remote-auto-connect' in ready_page.text
    assert f'/multiguard/panel/remote/workshop/session/{sid}/connect' in ready_page.text
    share_actions=[]
    original_share=workshop.meshcentral.create_share
    original_revoke=workshop.meshcentral.revoke_share
    def fake_share(node,label,caps,duration):
        assert node=="node/ci-mode-direct" and list(caps)==["desktop"]
        share_actions.append("create")
        return workshop.meshcentral.MeshShare(
            "ci-workshop-share","https://mesh.example.test/sharing?ci=1"
        )
    def fake_revoke(node,share_id):
        assert node=="node/ci-mode-direct"
        share_actions.append("revoke:"+share_id)
    workshop.meshcentral.create_share=fake_share
    workshop.meshcentral.revoke_share=fake_revoke
    try:
        opened=c.post(
            f"/multiguard/panel/remote/workshop/session/{sid}/connect",
            auth=auth,data={"csrf_token":token},follow_redirects=False
        )
        ensure(opened.status_code,200,"Consented workshop desktop")
        assert "owner-remote-desktop" in opened.text
        assert share_actions==["create"]
        ensure(c.post(
            f"/multiguard/panel/remote/workshop/session/{sid}/end",
            auth=auth,data={"csrf_token":token},follow_redirects=False
        ).status_code,303,"Owner closes MeshCentral workshop share")
        assert share_actions==["create","revoke:ci-workshop-share"]
        # A PRO->STANDARD switch must revoke a still-open desktop URL
        # synchronously, not wait for a 60s client poll.
        forced_sid=uuid.uuid4()
        with engine.begin() as db:
            db.execute(text("""
                INSERT INTO guard.workshop_remote_sessions(
                    id,installation_id,status,expires_at,mesh_public_id,
                    mesh_share_expires_at,granted_capabilities)
                VALUES(:sid,:iid,'ACTIVE',now()+interval '1 hour',
                    'ci-open-on-downgrade',now()+interval '1 hour',
                    '["desktop"]'::jsonb)
            """),{"sid":forced_sid,"iid":mode_direct})
        ensure(c.post(edition_url,auth=auth,data={
            "edition":"STANDARD","csrf_token":token
        },follow_redirects=False).status_code,303,"Service downgrade revokes external share")
        assert "revoke:ci-open-on-downgrade" in share_actions
        with engine.connect() as db:
            revoked=db.execute(text("""
                SELECT status,mesh_public_id FROM guard.workshop_remote_sessions
                WHERE id=:sid
            """),{"sid":forced_sid}).mappings().one()
        assert revoked["status"]=="EXPIRED" and revoked["mesh_public_id"] is None
        ensure(c.post('/multiguard/agent/workshop/remote/poll',
                      json=workshop_body()).status_code,200,"Standard agent poll")
        assert c.post('/multiguard/agent/workshop/remote/poll',
                      json=workshop_body()).json()["session"] is None
        ensure(c.post(edition_url,auth=auth,data={
            "edition":"PRO","csrf_token":token
        },follow_redirects=False).status_code,303,"Restore workshop PRO")
    finally:
        workshop.meshcentral.create_share=original_share
        workshop.meshcentral.revoke_share=original_revoke
    with engine.connect() as db:
        assert db.execute(text("""
            SELECT COUNT(*) FROM guard.license_links
            WHERE installation_id=:iid
        """),{"iid":mode_direct}).scalar_one()==0
    # Automatic MeshAgent association. No OWNER node field, no name match:
    # the discovery-authenticated installation sends its real local NodeId,
    # and MeshCtrl must verify that very node exists on this server.
    reg_url='/multiguard/agent/workshop/mesh-enroll'
    node_suffix="A"*64
    node_full="node//"+node_suffix
    original_lookup=workshop.meshcentral.verify_registered_node
    check_nodes=[]
    def fake_lookup(node):
        check_nodes.append(node)
        return node==node_full
    workshop.meshcentral.verify_registered_node=fake_lookup
    try:
        unauth={**workshop_body(),"discoveryCredential":"bogus-discovery-credential-0123456789","meshNodeId":node_suffix}
        ensure(c.post(reg_url,json=unauth).status_code,401,"No enrollment with foreign discovery identity")
        ensure(c.post(reg_url,json={**workshop_body(),"meshNodeId":"B"*64}).status_code,
               409,"Unregistered Mesh node rejected, even when discovery auth is valid")
        ensure(c.post(reg_url,json={**workshop_body(),"meshNodeId":node_suffix}).status_code,
               200,"Registered MeshAgent enrolled without owner action")
        assert check_nodes==["node//"+"B"*64,node_full]
        assert c.post(reg_url,json={**workshop_body(),"meshNodeId":node_suffix}).json()["accepted"]
        with engine.connect() as db:
            mapped=db.execute(text("""
                SELECT mesh_node_id FROM guard.workshop_mesh_nodes WHERE installation_id=:id
            """),{"id":mode_direct}).scalar_one()
        assert mapped==node_full
        assert 'POŁĄCZ</button>' in get(f'/multiguard/panel/remote?selected={mode_direct}').text
    finally:
        workshop.meshcentral.verify_registered_node=original_lookup
    print("PASS: MeshAgent self-registration requires discovery credentials and MeshCentral node verification.")
    print("PASS: Workshop PRO discovery authentication, consent, no KeyGate, MeshCentral closure and immediate downgrade safety.")

    ensure(get('/multiguard/panel/service-mode',False).status_code,401,'Private service mode')
    # Granted discovery-only installations must be in Computers, once, above paid ones.
    service_inventory=get('/multiguard/panel/computers').text
    assert service_inventory.count(f'data-installation="{mode_direct}"')==1
    assert service_inventory.index(f'data-installation="{mode_direct}"') < service_inventory.index(f'/multiguard/panel/device/{install_a}')
    assert 'SERWIS · PRO' in service_inventory
    assert f'data-installation="{mode_order}"' not in service_inventory
    # Equal-class installations sort by registration, independent of health/priority.
    with engine.begin() as db:
        db.execute(text("UPDATE guard.installations SET created_at='2020-01-01' WHERE id=:id"),{'id':install_a})
        db.execute(text("UPDATE guard.installations SET created_at='2025-01-01' WHERE id=:id"),{'id':install_b})
    sorted_inventory=get('/multiguard/panel/computers').text
    assert sorted_inventory.index(f'/multiguard/panel/device/{install_b}') < sorted_inventory.index(f'/multiguard/panel/device/{install_a}')
    if os.environ.get('OWNER_TEST_HTML_DIR'):
        (output/'service-mode.html').write_text(owner_modes.text,encoding='utf-8')
        (output/'computers.html').write_text(sorted_inventory,encoding='utf-8')

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
    # Search linked service-mode machines by reception number, never by
    # another machine's unrelated order; restore the original edition after.
    ensure(c.post(f"/multiguard/panel/workshop/{mode_order}/edition",auth=auth,
                  data={"edition":"PRO","csrf_token":token},
                  follow_redirects=False).status_code,303,
           "Temporary service PRO for order lookup")
    by_order=get("/multiguard/panel/remote?q=CI-2026-01234")
    ensure(by_order.status_code,200,"Remote lookup by service order number")
    assert f'selected={mode_order}' in by_order.text
    assert 'Zlecenie CI-2026-01234' in by_order.text
    assert f'selected={mode_direct}' not in by_order.text
    ensure(c.post(f"/multiguard/panel/workshop/{mode_order}/edition",auth=auth,
                  data={"edition":"STANDARD","csrf_token":token},
                  follow_redirects=False).status_code,303,"Restore service order STANDARD")
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

    # OWNER shortening uses the same absolute expiry operation as renewal.
    # KeyGate transport remains synthetic; SQL, routes and signatures are real.
    from datetime import timedelta
    from zoneinfo import ZoneInfo
    current_link=license._link_by_installation(direct_id)
    manage_url=f'/multiguard/panel/license/manage/{current_link["id"]}'
    short_url=manage_url+'/shorten'
    ensure(get(manage_url,False).status_code,401,'Licence management OWNER')
    manage_page=get(manage_url)
    ensure(manage_page.status_code,200,'Licence management')
    assert 'Przedłużenie' in manage_page.text
    assert 'class="owner-license-percent"' in manage_page.text
    assert 'Pozostało czasu licencji:' in manage_page.text
    assert 'name="paid_amount"' not in manage_page.text
    from datetime import datetime as _time, timezone as _utc
    start=_time(2026,1,1,tzinfo=_utc.utc)
    finish=_time(2026,1,11,tzinfo=_utc.utc)
    assert license._owner_remaining_percentage(start,finish,start)==100.0
    assert license._owner_remaining_percentage(start,finish,start+timedelta(days=5))==50.0
    assert license._owner_remaining_percentage(start,finish,finish)==0.0
    assert license._owner_remaining_percentage(start,finish,finish+timedelta(days=1))==0.0
    assert license._owner_remaining_percentage(start,finish,start-timedelta(days=1))==100.0
    assert license._owner_remaining_percentage(start,start,start) is None
    short_day=(license._utcnow()+timedelta(days=30)).astimezone(ZoneInfo('Europe/Warsaw')).date()
    short_form={'operation_id':str(uuid.uuid4()),
                'expected_end':license._iso(current_link['valid_until']),
                'new_last_day':short_day.isoformat(),
                'reason':'CI: korekta terminu <script>test</script>',
                'confirmed':'yes','csrf_token':license._workshop_csrf()}
    ensure(c.post(short_url,data=short_form).status_code,401,'Shortening OWNER')
    ensure(c.post(short_url,auth=auth,data={**short_form,'csrf_token':'bad'}).status_code,403,'Shortening CSRF')
    ensure(c.post(short_url,auth=auth,data={**short_form,'confirmed':''}).status_code,400,'Shortening confirmation')
    ensure(c.post(short_url,auth=auth,data={**short_form,'expected_end':short_day.isoformat()}).status_code,400,'Naive expiry rejected')
    ensure(c.post(short_url,auth=auth,data={**short_form,'new_last_day':'2000-01-01'}).status_code,400,'Past expiry rejected')
    ensure(c.post(short_url,auth=auth,data={**short_form,'new_last_day':'2099-01-01'}).status_code,400,'Extension through shortening rejected')
    ensure(c.post(short_url,auth=auth,data={**short_form,'expected_end':license._iso(current_link['valid_until']-timedelta(days=1))}).status_code,409,'Stale form rejected')
    before_calls=len(mock_calls['keygate_end'])
    real_set=license._keygate_set_valid_until
    def unavailable_keygate(*args):
        from fastapi import HTTPException
        raise HTTPException(502,'Synthetic KeyGate outage')
    license._keygate_set_valid_until=unavailable_keygate
    try:
        ensure(c.post(short_url,auth=auth,data=short_form).status_code,502,'KeyGate failure blocks shortening')
        assert license._link_by_installation(direct_id)['valid_until']==current_link['valid_until']
        with engine.connect() as db:
            assert db.execute(text('SELECT count(*) FROM guard.license_shortening WHERE license_link_id=:id'),{'id':current_link['id']}).scalar_one()==0
    finally:
        license._keygate_set_valid_until=real_set
    ensure(c.post(short_url,auth=auth,data=short_form,follow_redirects=False).status_code,303,'Shorten paid licence')
    ensure(c.post(short_url,auth=auth,data=short_form,follow_redirects=False).status_code,303,'Shortening double submit')
    ensure(c.post(short_url,auth=auth,data={**short_form,'reason':'Changed reason'}).status_code,409,'Operation ID reuse rejected')
    assert len(mock_calls['keygate_end'])==before_calls+1
    shortened=license._link_by_installation(direct_id)
    assert shortened['valid_from']==current_link['valid_from']
    assert shortened['accepted_documents']==current_link['accepted_documents']
    local_end=shortened['valid_until'].astimezone(ZoneInfo('Europe/Warsaw'))
    assert local_end.date()==short_day and (local_end.hour,local_end.minute,local_end.second)==(23,59,59)
    with engine.connect() as db:
        assert db.execute(text('SELECT count(*) FROM guard.license_shortening WHERE license_link_id=:id'),{'id':current_link['id']}).scalar_one()==1
        assert db.execute(text('SELECT valid_until FROM guard.installations WHERE installation_external_id=:id'),{'id':direct_id}).scalar_one()==shortened['valid_until']
    manage_page=get(manage_url)
    assert '&lt;script&gt;test&lt;/script&gt;' in manage_page.text
    assert manage_page.headers['cache-control']=='private, no-store'
    if os.environ.get('OWNER_TEST_HTML_DIR'):
        (output/'license-management.html').write_text(manage_page.text,encoding='utf-8')
    print('PASS: OWNER shortening, stale forms, duplicate submits, KeyGate outage rollback, history and installation expiry mirror.')

    # One licence key and an unchanged expiry through Standard <-> Pro.
    before_plan=license._link_by_installation(direct_id)
    plan_url=manage_url+'/change-plan'
    plan_info={'current':before_plan['keygate_plan_id'],
               'end':before_plan['valid_until'],'calls':0}
    fake_get_before=license._keygate_license
    fake_find_before=license._find_plan_id
    fake_change_before=license._keygate_change_plan
    def plan_remote_get(_):
        return {'status':'active','plan_id':plan_info['current'],
                'valid_until':license._iso(plan_info['end'])}
    def plan_find(edition,months):
        assert months==12
        return {'PRO':before_plan['keygate_plan_id'],
                'STANDARD':'ci-plan-standard-12m'}[edition]
    def plan_swap(_,new_plan):
        plan_info['current']=new_plan
        plan_info['calls']+=1
    license._keygate_license=plan_remote_get
    license._find_plan_id=plan_find
    license._keygate_change_plan=plan_swap
    try:
        swap={'operation_id':str(uuid.uuid4()),
              'expected_end':license._iso(before_plan['valid_until']),
              'target_edition':'STANDARD',
              'reason':'CI: przejscie na Standard bez nowej instalacji',
              'confirmed':'yes','csrf_token':license._workshop_csrf()}
        assert c.post(plan_url,data=swap).status_code==401
        assert c.post(plan_url,auth=auth,
                      data={**swap,'csrf_token':'bad'}).status_code==403
        assert c.post(plan_url,auth=auth,
                      data={**swap,'confirmed':''}).status_code==400
        assert c.post(plan_url,auth=auth,
                      data={**swap,'expected_end':license._iso(before_plan['valid_until']-timedelta(days=1))}).status_code==409
        from fastapi import HTTPException as _PlanErr
        def lost_response(lic_id,new_plan):
            plan_swap(lic_id,new_plan)
            raise _PlanErr(502,'CI: KeyGate odpowiedzial za pozno')
        license._keygate_change_plan=lost_response
        assert c.post(plan_url,auth=auth,data=swap).status_code==502
        assert 'id="license-plan-pending"' in get(manage_url).text
        assert license._link_by_installation(direct_id)['plan_code']=='multi_guard_pro'
        assert c.post('/v1/multi-guard/refresh',json=refresh_fields).status_code==409
        license._keygate_change_plan=plan_swap
        ensure(c.post(plan_url,auth=auth,data=swap,
                      follow_redirects=False).status_code,303,'Resume KeyGate plan')
        ensure(c.post(plan_url,auth=auth,data=swap,
                      follow_redirects=False).status_code,303,'Idempotent plan swap')
        assert plan_info['calls']==1
        after_plan=license._link_by_installation(direct_id)
        assert after_plan['plan_code']=='multi_guard'
        assert after_plan['valid_until']==before_plan['valid_until']
        assert after_plan['valid_from']==before_plan['valid_from']
        assert after_plan['license_key_hash']==before_plan['license_key_hash']
        # Old PRO agents must not overwrite server-authoritative STANDARD on
        # heartbeat before they download their fresh signed licence.
        stale_packet={
            'requestId':str(uuid.uuid4()),'nonce':'ci-plan-old-pro',
            'sentAt':'2026-10-14T10:00:00Z',
            'installationId':str(direct_id),'deviceId':direct_device,
            'installationCredential':refresh_fields['installationCredential'],
            'appVersion':'0.3.40','planCode':'PRO','licenseId':'wrong-client-lic',
            'lifecycle':'ACTIVE','validUntil':'2099-01-01T00:00:00Z',
            'healthLevel':'GREEN',
            'defender':{'available':True},
            'browserShield':{},
            'hardware':{}
        }
        ensure(c.post('/multiguard/agent/heartbeat',json=stale_packet).status_code,
               200,'Stale PRO heartbeat accepted as telemetry only')
        with engine.connect() as db:
            actual=db.execute(text("""
                SELECT plan_code,lifecycle,valid_until,license_id
                FROM guard.installations WHERE installation_external_id=:id
            """),{'id':direct_id}).mappings().one()
        assert actual['plan_code']=='STANDARD'
        assert actual['lifecycle']=='ACTIVE'
        assert actual['valid_until']==before_plan['valid_until']
        assert actual['license_id']==before_plan['keygate_license_id']
        with engine.connect() as db:
            assert db.execute(text("""
                SELECT plan_code FROM guard.installations
                WHERE installation_external_id=:id
            """),{'id':direct_id}).scalar_one()=='STANDARD'
        swap_back={**swap,'operation_id':str(uuid.uuid4()),
                   'target_edition':'PRO','reason':'CI: ponowne Pro'}
        ensure(c.post(plan_url,auth=auth,data=swap_back,
                      follow_redirects=False).status_code,303,'Return Pro')
        assert license._link_by_installation(direct_id)['plan_code']=='multi_guard_pro'
        assert license._link_by_installation(direct_id)['valid_until']==before_plan['valid_until']
        assert plan_info['calls']==2
    finally:
        license._keygate_license=fake_get_before
        license._find_plan_id=fake_find_before
        license._keygate_change_plan=fake_change_before
    assert 'Zmiana na Standard' in get(manage_url).text
    assert 'Zmiana na Pro' in get(manage_url).text
    print('PASS: existing-key Standard/Pro switch, preserved expiry, PENDING retry and auth.')

    # OWNER revocation is real KeyGate revoke+GET verification, not merely
    # deactivation nor a local status toggle. The fixture keeps the API fake.
    revoked_link=license._link_by_installation(direct_id)
    revoke_url=manage_url+'/revoke'
    assert 'id="license-revocation"' in get(manage_url).text
    initial_end=revoked_link['valid_until']
    revoke_form={"operation_id":str(uuid.uuid4()),
                 "expected_end":license._iso(initial_end),
                 "reason":"CI: cofniecie na zyczenie klienta <script>unsafe</script>",
                 "confirmed":"yes","csrf_token":license._workshop_csrf()}
    assert c.post(revoke_url,data=revoke_form).status_code==401
    assert c.post(revoke_url,auth=auth,
                  data={**revoke_form,"csrf_token":"invalid"}).status_code==403
    assert c.post(revoke_url,auth=auth,
                  data={**revoke_form,"confirmed":""}).status_code==400
    assert c.post(revoke_url,auth=auth,
                  data={**revoke_form,"expected_end":
                        license._iso(initial_end-timedelta(days=1))}).status_code==409
    from fastapi import HTTPException as CI_HTTPException
    real_get=license._keygate_license
    real_revoke=getattr(license,"_keygate_revoke")
    remote_status={"value":"active","post_calls":0}
    def fake_remote_get(license_id):
        assert license_id=="fake-direct-ci"
        return {"status":remote_status["value"]}
    def lost_keygate_response(license_id):
        assert license_id=="fake-direct-ci"
        remote_status["post_calls"]+=1
        remote_status["value"]="revoked"
        raise CI_HTTPException(502,"CI: response lost after successful revoke")
    def no_double_post(license_id):
        raise AssertionError("A verified revoked license must not be revoked twice")
    license._keygate_license=fake_remote_get
    license._keygate_revoke=lost_keygate_response
    try:
        assert c.post(revoke_url,auth=auth,data=revoke_form).status_code==502
        assert license._link_by_installation(direct_id)['lifecycle']=="ACTIVE"
        with engine.connect() as db:
            assert db.execute(text("""
                SELECT count(*) FROM guard.license_revocations
                WHERE license_link_id=:id
            """),{"id":revoked_link['id']}).scalar_one()==0
        license._keygate_revoke=no_double_post
        success=c.post(revoke_url,auth=auth,data=revoke_form,follow_redirects=False)
        ensure(success.status_code,303,"Revoke verified against KeyGate")
        ensure(c.post(revoke_url,auth=auth,data=revoke_form,
                      follow_redirects=False).status_code,303,
               "Revocation duplicate submission")
        assert remote_status["post_calls"]==1
        assert c.post(revoke_url,auth=auth,data={
            **revoke_form,"reason":"different reason"
        }).status_code==409
    finally:
        license._keygate_revoke=real_revoke
        license._keygate_license=real_get
    revoked_state=license._link_by_installation(direct_id)
    assert revoked_state["lifecycle"]=="REVOKED"
    assert revoked_state["valid_from"]==revoked_link["valid_from"]
    assert revoked_state["accepted_documents"]==revoked_link["accepted_documents"]
    with engine.connect() as db:
        state=db.execute(text("""
            SELECT lifecycle FROM guard.installations
            WHERE installation_external_id=:id
        """),{"id":direct_id}).scalar_one()
        audit=db.execute(text("""
            SELECT count(*) FROM guard.license_revocations
            WHERE license_link_id=:id
        """),{"id":revoked_link["id"]}).scalar_one()
    assert state=="REVOKED" and audit==1
    revocation_page=get(manage_url)
    assert "Cofnięta · poprzedni termin ważności" in revocation_page.text
    assert "Historia zmian licencji" in revocation_page.text
    assert "Pozostawało w chwili cofnięcia:" in revocation_page.text
    assert 'class="owner-license-percent"' in revocation_page.text
    assert "Cofnięcie" in revocation_page.text
    assert "&lt;script&gt;unsafe&lt;/script&gt;" in revocation_page.text
    assert 'id="license-revocation"' not in revocation_page.text
    assert c.post(revoke_url,auth=auth,data={
        **revoke_form,"operation_id":str(uuid.uuid4())
    }).status_code==409
    print("PASS: OWNER KeyGate revocation verified, retry after lost response, 401/403/409, single audit and signed state mirror.")



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

    # The browser endpoints reuse actual remote-session consent and audit logic.
    # Only MeshCentral transport is replaced; never contact a real customer.
    remote=importlib.import_module('app.routers.multiguard_remote')
    remote._ensure_schema()
    support_id=uuid.uuid4()
    with engine.begin() as db:
        db.execute(text("UPDATE guard.installations SET mesh_node_id='ci-node-123', lifecycle='ACTIVE', valid_until=now()+interval '1 day' WHERE id=:id"),{'id':install_b})
        db.execute(text("""INSERT INTO guard.support_requests
            (id,local_request_id,installation_id,service_device_id,subject,description,created_at)
            VALUES (:id,:local,:install,:device,'CI zdalna pomoc','Synthetic only',now())"""),
            {'id':support_id,'local':uuid.uuid4(),'install':install_b,'device':pc_b})
        # The PRO installation has one real synthetic link, enabling a full
        # KeyGate-revoke -> MeshCentral-share-close contract regression.
        db.execute(text("""
            INSERT INTO guard.license_links(
                reception_id,reception_number,service_device_id,
                keygate_license_id,keygate_plan_id,license_key_hash,
                plan_code,duration_months,release_channel,lifecycle,
                installation_id,device_id,credential_sha256,valid_until)
            SELECT :order_id,'CI-REMOTE-LIC',:device_id,
                   'ci-keygate-remote-pro','ci-keygate-plan',:key_hash,
                   'multi_guard_pro',12,'STABLE','ACTIVE',
                   installation_external_id,'test-dh',:cred,
                   now()+interval '1 day'
            FROM guard.installations WHERE id=:internal_id
        """),{'order_id':order_b,'device_id':pc_b,'key_hash':'7'*64,
              'cred':'1'*64,'internal_id':install_b})
    # During a Standard/Pro conversion, both the OWNER workspace and the
    # underlying routes must fail closed. No fake "request consent" action.
    with engine.begin() as db:
        linked=db.execute(text("""
            SELECT id,keygate_plan_id,valid_until FROM guard.license_links
            WHERE reception_id=:order_id
        """),{"order_id":order_b}).mappings().one()
        pending_remote_op=uuid.uuid4()
        db.execute(text("""
            INSERT INTO guard.license_plan_changes(
                id,license_link_id,old_plan_code,new_plan_code,
                old_keygate_plan_id,new_keygate_plan_id,
                expected_valid_until,reason,status
            ) VALUES (:op,:link,'multi_guard_pro','multi_guard',
                     :old_plan,'ci-standard-remote',
                     :expires,'CI test niedokonczonej zmiany','PENDING')
        """), {"op":pending_remote_op,"link":linked["id"],
                "old_plan":linked["keygate_plan_id"],
                "expires":linked["valid_until"]})
    pending_remote_page=get(f'/multiguard/panel/remote?selected={install_b}')
    ensure(pending_remote_page.status_code,200,'Pending plan remote workspace')
    assert 'Trwa zmiana edycji licencji' in pending_remote_page.text
    assert 'POPROŚ O ZGODĘ NA SESJĘ' not in pending_remote_page.text
    pending_remote_form={'support_id':str(support_id),
                         'csrf_token':license._workshop_csrf()}
    ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                  data=pending_remote_form).status_code,403,
           'OWNER cannot request consent during pending plan change')
    with engine.begin() as db:
        db.execute(text("""
            DELETE FROM guard.license_plan_changes
            WHERE id=:id AND status='PENDING'
        """), {"id":pending_remote_op})

    ensure(get('/multiguard/panel/remote',False).status_code,401,'Private remote page')
    remote_page=get(f'/multiguard/panel/remote?selected={install_b}')
    ensure(remote_page.status_code,200,'Remote workspace')
    assert 'CI zdalna pomoc' in remote_page.text
    ensure(get(f'/multiguard/panel/remote?selected={install_a}').status_code,404,'Standard excluded from remote workspace')
    remote_csrf=license._workshop_csrf()
    remote_form={'support_id':str(support_id),'csrf_token':remote_csrf}
    ensure(c.post('/multiguard/panel/remote/request',data=remote_form).status_code,401,'Remote mutation OWNER')
    ensure(c.post('/multiguard/panel/remote/request',auth=auth,data={**remote_form,'csrf_token':'bad'}).status_code,403,'Remote mutation CSRF')
    ensure(c.post('/multiguard/panel/remote/request',auth=auth,data=remote_form,follow_redirects=False).status_code,303,'Request client consent')
    with engine.connect() as db:
        sid=db.execute(text('SELECT id FROM guard.remote_sessions WHERE support_request_id=:id'),{'id':support_id}).scalar_one()
    connect=f'/multiguard/panel/remote/{sid}/connect'
    ensure(c.post(connect,auth=auth,data={'csrf_token':remote_csrf}).status_code,409,'No desktop without client consent')
    mesh_calls=[]
    original_create=remote.meshcentral.create_share
    original_revoke=remote.meshcentral.revoke_share
    os.environ['MESH_CENTRAL_URL']='wss://mesh.example.test/control.ashx'
    remote.meshcentral.create_share=lambda *args: (mesh_calls.append('create') or remote.meshcentral.MeshShare('ci-share','https://mesh.example.test/sharing?ci=1'))
    remote.meshcentral.revoke_share=lambda *args: mesh_calls.append('revoke')
    try:
        with engine.begin() as db:
            db.execute(text("UPDATE guard.remote_sessions SET status='CONSENTED',granted_capabilities='[\"desktop\"]'::jsonb WHERE id=:id"),{'id':sid})
        # The Mesh share may be created while OWNER rebinds a node. The
        # final backend transaction must reject the stale node and revoke
        # the newly created, uncommitted share before returning an error.
        initial_node='ci-node-123'
        rebind_node='node/ci-race-new-node'
        old_share_create=remote.meshcentral.create_share
        def race_share(*args):
            mesh_calls.append('create')
            with engine.begin() as db:
                db.execute(text("""
                    UPDATE guard.installations SET mesh_node_id=:node
                    WHERE id=:id
                """),{'id':install_b,'node':rebind_node})
            return remote.meshcentral.MeshShare(
                'ci-race-share','https://mesh.example.test/sharing?race=1')
        remote.meshcentral.create_share=race_share
        try:
            ensure(c.post(connect,auth=auth,
                          data={'csrf_token':remote_csrf}).status_code,403,
                   'Remote opening must reject a concurrently rebound Mesh node')
            assert mesh_calls==['create','revoke']
            with engine.connect() as db:
                uncommitted=db.execute(text("""
                    SELECT status,mesh_public_id FROM guard.remote_sessions
                    WHERE id=:id
                """),{'id':sid}).mappings().one()
            assert uncommitted['status']=='CONSENTED'
            assert uncommitted['mesh_public_id'] is None
        finally:
            remote.meshcentral.create_share=old_share_create
            with engine.begin() as db:
                db.execute(text("""
                    UPDATE guard.installations SET mesh_node_id=:node
                    WHERE id=:id
                """),{'id':install_b,'node':initial_node})
        mesh_calls.clear()
        desktop=c.post(connect,auth=auth,data={'csrf_token':remote_csrf})
        ensure(desktop.status_code,200,'Consented remote desktop')
        # OWNER cannot change Mesh node while a public URL is outstanding.
        with engine.connect() as db:
            bound_external=db.execute(text("""
                SELECT installation_external_id FROM guard.installations
                WHERE id=:id
            """),{'id':install_b}).scalar_one()
        from fastapi import HTTPException as CIMeshRebindError
        try:
            remote.bind_mesh_node(
                remote.MeshBindBody(
                    installationId=bound_external,
                    meshNodeId='node/ci-different-node'
                ),
                security.CurrentUser(),
            )
            raise AssertionError('Rebinding an active share must be rejected')
        except CIMeshRebindError as exc:
            assert exc.status_code==409
        with engine.connect() as db:
            assert db.execute(text("""
                SELECT mesh_node_id FROM guard.installations WHERE id=:id
            """),{'id':install_b}).scalar_one()==initial_node
        assert 'id="owner-remote-desktop"' in desktop.text
        assert 'src="https://mesh.example.test/sharing?ci=1"' in desktop.text
        assert desktop.headers['cache-control']=='private, no-store'
        assert mesh_calls==['create']
        with engine.begin() as db:
            db.execute(text("UPDATE guard.installations SET lifecycle='EXPIRED' WHERE id=:id"),{'id':install_b})
        ensure(c.post(connect,auth=auth,data={'csrf_token':remote_csrf}).status_code,403,'Expired licence cannot reconnect')
        end=f'/multiguard/panel/remote/{sid}/end'
        ensure(c.post(end,auth=auth,data={'csrf_token':'bad'}).status_code,403,'End requires CSRF')
        def failed_mesh_revoke(*_):
            raise remote.meshcentral.MeshCentralError('CI: mesh not available')
        previous_revoke=remote.meshcentral.revoke_share
        remote.meshcentral.revoke_share=failed_mesh_revoke
        try:
            ensure(c.post(end,auth=auth,data={'csrf_token':remote_csrf},
                          follow_redirects=False).status_code,502,
                   'Failed Mesh revoke must not close a still-live remote link')
            with engine.connect() as db:
                still_open=db.execute(text("""
                    SELECT status,mesh_public_id FROM guard.remote_sessions
                    WHERE id=:id
                """),{'id':sid}).mappings().one()
            assert still_open['status']=='CONNECT_READY'
            assert still_open['mesh_public_id']=='ci-share'
        finally:
            remote.meshcentral.revoke_share=previous_revoke
        ensure(c.post(end,auth=auth,data={'csrf_token':remote_csrf},
                      follow_redirects=False).status_code,303,'Owner ends session')
        assert mesh_calls==['create','revoke']
        with engine.connect() as db:
            final_status=db.execute(text("""
                SELECT status,mesh_public_id,ended_at
                FROM guard.remote_sessions WHERE id=:id
            """),{'id':sid}).mappings().one()
        assert final_status['status']=='ENDED'
        assert final_status['mesh_public_id'] is None and final_status['ended_at']

        # Keep the preceding negative entitlement test intact. A fresh
        # consent-expiration test needs an ACTIVE licence: otherwise OWNER's
        # correct 403 blocks creation before consent can expire.
        ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                      data=remote_form,follow_redirects=False).status_code,403,
               'Expired licence refuses new consent before expiry test')
        with engine.begin() as db:
            db.execute(text("""
                UPDATE guard.installations SET lifecycle='ACTIVE'
                WHERE id=:id AND lifecycle='EXPIRED'
            """), {'id':install_b})
        # Stale CONNECT_READY sharing must be revoked before auto-expiry.
        auto_expired_id=uuid.uuid4()
        with engine.begin() as db:
            db.execute(text("""
                INSERT INTO guard.remote_sessions (
                    id,support_request_id,installation_id,service_device_id,
                    requested_by_name,status,expires_at,mesh_public_id,
                    mesh_share_expires_at,granted_capabilities)
                VALUES (:id,:support,:install,:device,'CI auto-expire',
                    'CONNECT_READY',now()+interval '1 day',
                    'ci-auto-expire',now()-interval '1 minute',
                    '["desktop"]'::jsonb)
            """), {'id':auto_expired_id,'support':support_id,
                   'install':install_b,'device':pc_b})
        original_revoke=remote.meshcentral.revoke_share
        def auto_expire_unavailable(*args):
            raise remote.meshcentral.MeshCentralError('CI MeshCtrl offline')
        remote.meshcentral.revoke_share=auto_expire_unavailable
        try:
            from fastapi import HTTPException as CIExpiryError
            try:
                with engine.begin() as db:
                    remote._expire_and_find_open(db,install_b)
                raise AssertionError('MeshCentral outage must block SQL expiry')
            except CIExpiryError as exc:
                assert exc.status_code==502
            with engine.connect() as db:
                status=db.execute(text("""
                    SELECT status,mesh_public_id FROM guard.remote_sessions
                    WHERE id=:id
                """),{'id':auto_expired_id}).mappings().one()
            assert status['status']=='CONNECT_READY'
            assert status['mesh_public_id']=='ci-auto-expire'
        finally:
            remote.meshcentral.revoke_share=original_revoke
        auto_close_calls=[]
        def auto_expire_revoke(node_id,public_id):
            assert node_id=='ci-node-123' and public_id=='ci-auto-expire'
            auto_close_calls.append(public_id)
        remote.meshcentral.revoke_share=auto_expire_revoke
        try:
            with engine.begin() as db:
                assert remote._expire_and_find_open(db,install_b) is None
        finally:
            remote.meshcentral.revoke_share=original_revoke
        assert auto_close_calls==['ci-auto-expire']
        with engine.connect() as db:
            status=db.execute(text("""
                SELECT status,mesh_public_id,ended_at FROM guard.remote_sessions
                WHERE id=:id
            """),{'id':auto_expired_id}).mappings().one()
            audited=db.execute(text("""
                SELECT count(*) FROM guard.remote_session_events
                WHERE remote_session_id=:id AND event_type='SESSION_EXPIRED'
            """),{'id':auto_expired_id}).scalar_one()
        assert status['status']=='EXPIRED' and status['mesh_public_id'] is None
        assert status['ended_at'] is not None and audited==1

        # When PRO entitlement itself expires before the 60-minute share,
        # a client poll must still revoke the external link and persist expiry.
        lost_entitlement_id=uuid.uuid4()
        with engine.begin() as db:
            db.execute(text("""
                INSERT INTO guard.remote_sessions (
                    id,support_request_id,installation_id,service_device_id,
                    requested_by_name,status,expires_at,mesh_public_id,
                    mesh_share_expires_at,granted_capabilities)
                VALUES (:id,:support,:install,:device,'CI entitlement',
                    'CONNECT_READY',now()+interval '1 day',
                    'ci-entitlement-open',now()+interval '30 minutes',
                    '["desktop"]'::jsonb)
            """), {'id':lost_entitlement_id,'support':support_id,
                   'install':install_b,'device':pc_b})
            db.execute(text("""
                UPDATE guard.installations SET lifecycle='EXPIRED'
                WHERE id=:id
            """), {'id':install_b})
        old_require=remote._require_agent
        prior_mesh_revoke=remote.meshcentral.revoke_share
        forced_revokes=[]
        def expired_agent(conn, external_id, device_id, credential):
            return {'id':install_b,'service_device_id':pc_b,
                    'plan_code':'PRO','lifecycle':'EXPIRED','is_current':True,
                    'valid_until':_time.now(_utc.utc)+timedelta(days=1)}
        def forced_revoke(node_id, public_id):
            forced_revokes.append((node_id, public_id))
        remote._require_agent=expired_agent
        remote.meshcentral.revoke_share=forced_revoke
        try:
            poll=remote.agent_remote_poll(remote.AgentRemoteAuthBody(
                requestId=str(uuid.uuid4()),nonce='ci-entitlement-lost',
                sentAt=_time.now(_utc.utc),
                installationId=uuid.uuid4(),deviceId='ci-expired-device-123456789',
                installationCredential='ci-credential-not-for-production-1234567890',
            ))
            assert poll['session'] is None
        finally:
            remote._require_agent=old_require
            remote.meshcentral.revoke_share=prior_mesh_revoke
        assert forced_revokes==[('ci-node-123','ci-entitlement-open')]
        with engine.connect() as db:
            expired=db.execute(text("""
                SELECT status,mesh_public_id FROM guard.remote_sessions WHERE id=:id
            """),{'id':lost_entitlement_id}).mappings().one()
            audit=db.execute(text("""
                SELECT count(*) FROM guard.remote_session_events
                WHERE remote_session_id=:id AND event_type='PRO_ENTITLEMENT_LOST'
            """),{'id':lost_entitlement_id}).scalar_one()
        assert expired['status']=='EXPIRED' and expired['mesh_public_id'] is None
        assert audit==1
        with engine.begin() as db:
            db.execute(text("""
                UPDATE guard.installations SET lifecycle='ACTIVE' WHERE id=:id
            """),{'id':install_b})

        # Both expiry decisions must commit EXPIRED with an audit event.
        ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                      data=remote_form,follow_redirects=False).status_code,303,
               'New request for expired consent')
        with engine.begin() as db:
            expired_id=db.execute(text("""
                SELECT id FROM guard.remote_sessions WHERE support_request_id=:id
                AND status='REQUESTED' ORDER BY requested_at DESC LIMIT 1
            """),{'id':support_id}).scalar_one()
            db.execute(text("""
                UPDATE guard.remote_sessions SET status='CONSENTED',
                granted_capabilities='["desktop"]'::jsonb,
                expires_at=now()-interval '1 minute' WHERE id=:id
            """),{'id':expired_id})
        ensure(c.post(f'/multiguard/panel/remote/{expired_id}/connect',
                      auth=auth,data={'csrf_token':remote_csrf}).status_code,410,
               'Expired consent must return 410')
        with engine.connect() as db:
            assert db.execute(text("""
                SELECT status FROM guard.remote_sessions WHERE id=:id
            """),{'id':expired_id}).scalar_one()=='EXPIRED'
            assert db.execute(text("""
                SELECT count(*) FROM guard.remote_session_events
                WHERE remote_session_id=:id AND event_type='CONSENT_EXPIRED'
            """),{'id':expired_id}).scalar_one()==1
        assert mesh_calls==['create','revoke']
        ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                      data=remote_form,follow_redirects=False).status_code,303,
               'New request for expired client reply')
        with engine.begin() as db:
            request_id=db.execute(text("""
                SELECT id FROM guard.remote_sessions WHERE support_request_id=:id
                AND status='REQUESTED' ORDER BY requested_at DESC LIMIT 1
            """),{'id':support_id}).scalar_one()
            db.execute(text("""
                UPDATE guard.remote_sessions SET expires_at=now()-interval '1 minute'
                WHERE id=:id
            """),{'id':request_id})
            installation_external=db.execute(text("""
                SELECT installation_external_id FROM guard.installations WHERE id=:id
            """),{'id':install_b}).scalar_one()
        old_require=remote._require_agent
        def simulated_agent(connection, installation_id, device_id, credential):
            assert installation_id==installation_external
            return {'id':install_b,'service_device_id':pc_b,
                    'plan_code':'PRO','lifecycle':'ACTIVE',
                    'valid_until':_time.now(_utc.utc)+timedelta(days=1)}
        remote._require_agent=simulated_agent
        try:
            response=remote.agent_remote_decision(remote.AgentRemoteDecisionBody(
                requestId=str(uuid.uuid4()),nonce='ci-expiration',
                sentAt=_time.now(_utc.utc),installationId=installation_external,
                deviceId='synthetic-test-device-id-1234',
                installationCredential='synthetic-credential-1234567890-abcdefgh',
                sessionId=request_id,allowDesktop=True,
            ))
            assert response.status_code==410
        finally:
            remote._require_agent=old_require
        with engine.connect() as db:
            assert db.execute(text("""
                SELECT status FROM guard.remote_sessions WHERE id=:id
            """),{'id':request_id}).scalar_one()=='EXPIRED'
            assert db.execute(text("""
                SELECT count(*) FROM guard.remote_session_events
                WHERE remote_session_id=:id AND event_type='CLIENT_REQUEST_EXPIRED'
            """),{'id':request_id}).scalar_one()==1

        # A renewed consented session MUST be closed when the PRO licence is
        # revoked. This uses synthetic KeyGate and MeshCentral transports.
        with engine.begin() as db:
            db.execute(text("UPDATE guard.installations SET lifecycle='ACTIVE' WHERE id=:id"),{'id':install_b})
        ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                      data=remote_form,follow_redirects=False).status_code,303,
               'Second help session')
        with engine.begin() as db:
            sid2=db.execute(text("""
                SELECT id FROM guard.remote_sessions WHERE support_request_id=:id
                ORDER BY requested_at DESC LIMIT 1
            """),{'id':support_id}).scalar_one()
            assert sid2!=sid
            db.execute(text("""
                UPDATE guard.remote_sessions SET status='CONSENTED',
                    granted_capabilities='["desktop"]'::jsonb WHERE id=:id
            """),{'id':sid2})
        connect2=f'/multiguard/panel/remote/{sid2}/connect'
        ensure(c.post(connect2,auth=auth,
                      data={'csrf_token':remote_csrf}).status_code,200,
               'Second consented desktop')
        assert mesh_calls==['create','revoke','create']
        link_for_remote=license._link_by_reception_id(order_b)
        assert link_for_remote and link_for_remote['lifecycle']=='ACTIVE'
        remote_keygate={'state':'active','revocations':0}
        saved_get,saved_revoke=license._keygate_license,license._keygate_revoke
        def remote_test_get(license_id):
            assert license_id=='ci-keygate-remote-pro'
            return {'status':remote_keygate['state']}
        def remote_test_revoke(license_id):
            assert license_id=='ci-keygate-remote-pro'
            remote_keygate['revocations']+=1
            remote_keygate['state']='revoked'
        license._keygate_license=remote_test_get
        license._keygate_revoke=remote_test_revoke
        try:
            revoke_payload={'operation_id':str(uuid.uuid4()),
                            'expected_end':license._iso(link_for_remote['valid_until']),
                            'reason':'CI: zakonczenie licencji Pro i sesji zdalnej',
                            'confirmed':'yes','csrf_token':license._workshop_csrf()}
            revoke_path=f"/multiguard/panel/license/manage/{link_for_remote['id']}/revoke"
            ensure(c.post(revoke_path,auth=auth,data=revoke_payload,
                          follow_redirects=False).status_code,303,
                   'Revoke Pro and close MeshCentral')
            assert mesh_calls==['create','revoke','create','revoke']
            assert remote_keygate['revocations']==1
            with engine.connect() as db:
                closed=db.execute(text("""
                    SELECT status,mesh_public_id,ended_at FROM guard.remote_sessions
                    WHERE id=:id
                """),{'id':sid2}).mappings().one()
                current=db.execute(text("""
                    SELECT lifecycle FROM guard.installations WHERE id=:id
                """),{'id':install_b}).scalar_one()
                audit_count=db.execute(text("""
                    SELECT count(*) FROM guard.remote_session_events
                    WHERE remote_session_id=:id AND event_type='LICENSE_REVOKED'
                """),{'id':sid2}).scalar_one()
            assert closed['status']=='ENDED' and closed['mesh_public_id'] is None
            assert closed['ended_at'] is not None and current=='REVOKED'
            assert audit_count==1
            ensure(c.post(connect2,auth=auth,
                          data={'csrf_token':remote_csrf}).status_code,403,
                   'OWNER cannot reopen remote after licence revoke')
            from types import SimpleNamespace as _Actor
            from fastapi import HTTPException as _HttpError
            try:
                remote.remote_session_connect(str(sid2),_Actor(display_name='OWNER CI'))
                raise AssertionError('Direct API must block revoked Pro entitlement')
            except _HttpError as exc:
                assert exc.status_code==403
            ensure(c.post('/multiguard/panel/remote/request',auth=auth,
                          data=remote_form).status_code,403,
                   'OWNER cannot create a session after licence revoke')
            ensure(c.post(revoke_path,auth=auth,data=revoke_payload,
                          follow_redirects=False).status_code,303,
                   'Revocation retry idempotent')
            assert remote_keygate['revocations']==1
            assert mesh_calls==['create','revoke','create','revoke']
        finally:
            license._keygate_license=saved_get
            license._keygate_revoke=saved_revoke
        if os.environ.get('OWNER_TEST_HTML_DIR'):
            (output/'remote.html').write_text(remote_page.text,encoding='utf-8')
    finally:
        remote.meshcentral.create_share=original_create
        remote.meshcentral.revoke_share=original_revoke
    print('PASS: six-section OWNER work, service-first inventory, remote auth/CSRF/consent/expiry/end; MeshCentral transport mocked.')
    print("PASS: read-only owner-panel schema and media-root preflight.")
    print("PASS: PostgreSQL + actual FastAPI owner routes, private media, device links,")
    print("      CSRF forms, configurable status, audited inactive diagnostic renewals.")
