"""OWNER browser actions for remote help.

The web panel uses existing HTTP Basic OWNER authentication. Never expose
the separately authenticated mobile-owner remote API to browser JavaScript.
Every state-changing browser action also requires a rotating CSRF token.
Workshop sessions require a current signed PRO grant and explicit client
consent; absent MeshAgent fails closed. Commercial PRO sessions keep their
separate support-ticket lifecycle and are not provisioned through this route.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.routers.multiguard_license import _panel_auth
from app.routers.multiguard_panel_settings import _token_valid
from app.routers import multiguard_workshop_remote as workshop

router = APIRouter(tags=["multiguard-owner-remote-browser"])


class OwnerBrowserCsrf(BaseModel):
    csrfToken: str = Field(min_length=10, max_length=256)


class OwnerBrowserStart(OwnerBrowserCsrf):
    installationId: uuid.UUID


def _check_csrf(value: str):
    if not _token_valid(value):
        raise HTTPException(403, "Sesja formularza wygasła. Odśwież panel.")


def _owner():
    return SimpleNamespace(username="Multi-Servis OWNER")


@router.post("/multiguard/panel/remote/start")
def owner_browser_remote_start(body: OwnerBrowserStart, _: None = Depends(_panel_auth)):
    _check_csrf(body.csrfToken)
    # User-supplied ID is a full UUID, never just the public MG-XXXXXXXX label.
    # Workshop PRO and physical MeshAgent binding are rechecked in the callee.
    return workshop.owner_start_workshop_remote(
        workshop.OwnerWorkshopRequest(
            installationId=body.installationId,
            requestFiles=False,
            subject="Zdalna pomoc Multi-Servis",
        ), user=_owner()
    )


@router.get("/multiguard/panel/remote/session/{session_id}")
def owner_browser_remote_status(session_id: uuid.UUID, _: None = Depends(_panel_auth)):
    return workshop.owner_workshop_remote_detail(session_id, user=_owner())


@router.post("/multiguard/panel/remote/session/{session_id}/connect")
def owner_browser_remote_connect(session_id: uuid.UUID, body: OwnerBrowserCsrf,
                                 _: None = Depends(_panel_auth)):
    _check_csrf(body.csrfToken)
    # This only succeeds after the remote client's explicit and non-expired
    # consent; MeshCentral issues a short-lived expiring link.
    return workshop.owner_workshop_remote_connect(session_id, user=_owner())


@router.post("/multiguard/panel/remote/session/{session_id}/end")
def owner_browser_remote_end(session_id: uuid.UUID, body: OwnerBrowserCsrf,
                             _: None = Depends(_panel_auth)):
    _check_csrf(body.csrfToken)
    # If revocation of the Mesh share cannot be confirmed, backend returns
    # 502 and the browser must not report success.
    return workshop.owner_workshop_remote_end(session_id, user=_owner())
