"""MASTER 1.5 OWNER Mesh group retry endpoint.

The existing Save remains authoritative. This router never alters an edition.
"""
from __future__ import annotations
import asyncio
from uuid import UUID
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.database import engine
from app.routers import multiguard_license as license
from app.routers import master15_owner_mesh_sync_engine as sync

router=APIRouter(tags=["multi-guard-mesh-groups"])

def _spawn_sync(iid: UUID) -> None:
    task=asyncio.create_task(asyncio.to_thread(sync.run_pending_installation,engine,iid))
    task.add_done_callback(_task_finished)

def _task_finished(task:asyncio.Task) -> None:
    # Exceptions never reveal Mesh IDs, credentials, or tokens to the client.
    try:
        task.result()
    except Exception:
        import logging
        logging.getLogger("multiguard.owner.mesh").exception("Mesh sync worker failed")

@router.post("/multiguard/panel/licenses-grid/{link_id}/mesh-retry")
async def retry_group_sync(
    link_id:UUID,
    csrf_token:str=Form(...),
    _:None=Depends(license._panel_auth),
):
    if not license._token_valid(csrf_token):
        raise HTTPException(403,"Wygasły formularz OWNER.")
    with engine.begin() as db:
        row=db.execute(text("""
            SELECT installation_id FROM guard.license_links WHERE id=:id
        """),{"id":link_id}).mappings().first()
        if not row or not row["installation_id"]:
            raise HTTPException(404,"Komputer nie ma aktywnej instalacji.")
        iid=row["installation_id"]
        if not sync.request_manual_retry(db,iid):
            raise HTTPException(409,"Ponowienie nie jest dostępne.")
    _spawn_sync(iid)
    return RedirectResponse("/multiguard/panel/licenses-grid",status_code=303,
        headers={"Cache-Control":"private, no-store"})
