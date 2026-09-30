from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
from datetime import datetime, timezone

from dateutil.relativedelta import relativedelta
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .db import (
    by_installation,
    by_key,
    by_license,
    by_reception,
    create_link,
    hash_secret,
    init_schema,
    keygate_plan_by_slug,
    list_recent,
    update_link,
    utcnow,
)
from .keygate import keygate
from .models import AcceptanceRequest, ApproveRequest, ProvisionRequest, RefreshRequest
from .signing import public_key_b64, signed_envelope, validate_signing_key


KEY_PATTERN = re.compile(
    r"^KG-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}$"
)

app = FastAPI(title="Multi-Guard License Bridge", version="0.1.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="strict",
    https_only=settings.public_base_url.startswith("https://"),
)


@app.on_event("startup")
def startup() -> None:
    init_schema()
    validate_signing_key()


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def plan_label(plan_code: str) -> str:
    return "Multi-Guard Pro" if plan_code == "multi_guard_pro" else "Multi-Guard"


def load_required_documents() -> list[dict[str, str]]:
    raw = os.getenv("BRIDGE_REQUIRED_DOCUMENTS_JSON", "").strip()
    if not raw:
        return []
    try:
        source = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("BRIDGE_REQUIRED_DOCUMENTS_JSON is invalid JSON") from exc
    if not isinstance(source, list):
        raise RuntimeError("BRIDGE_REQUIRED_DOCUMENTS_JSON must be an array")

    result: list[dict[str, str]] = []
    for item in source:
        if not isinstance(item, dict):
            raise RuntimeError("Required document must be an object")
        kind = str(item.get("kind", "")).strip()
        version = str(item.get("version", "")).strip()
        title = str(item.get("title", "")).strip()
        content = str(item.get("content_markdown", ""))
        if not all((kind, version, title, content)):
            raise RuntimeError(
                "Required document needs kind, version, title and content_markdown"
            )
        result.append(
            {
                "kind": kind,
                "version": version,
                "title": title,
                "contentMarkdown": content,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )
    return result


def require_service_token(
    authorization: str | None = Header(default=None),
) -> None:
    expected = f"Bearer {settings.service_token}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(401, "Unauthorized")


def require_admin(request: Request) -> None:
    if request.session.get("admin") is not True:
        raise HTTPException(401, "Login required")


def authenticate_installation(req: RefreshRequest):
    link = by_installation(req.installation_id)
    if not link:
        raise HTTPException(404, "Installation not found")
    if link.get("device_id") != req.device_id:
        raise HTTPException(403, "Device mismatch")
    expected = link.get("credential_hash") or ""
    actual = hash_secret(req.installation_credential)
    if not expected or not secrets.compare_digest(expected, actual):
        raise HTTPException(403, "Invalid installation credential")
    return link


async def refresh_lifecycle(link):
    data = await keygate.get_license(link["keygate_license_id"])
    status = str(data.get("status", "")).lower()
    lifecycle = link["lifecycle"]

    if status in {"revoked", "suspended", "canceled"}:
        lifecycle = "REVOKED"
    elif status == "expired":
        lifecycle = "EXPIRED"
    elif link.get("valid_until") and utcnow() >= link["valid_until"]:
        lifecycle = "EXPIRED"

    if lifecycle != link["lifecycle"]:
        update_link(link["keygate_license_id"], lifecycle=lifecycle)
        link = by_license(link["keygate_license_id"])
    return link


@app.get("/")
def root():
    return RedirectResponse("/admin", status_code=303)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/multi-guard/license/pubkey")
def license_pubkey():
    return {
        "algorithm": "ed25519",
        "format": "base64",
        "public_key": public_key_b64(),
    }


@app.post("/v1/multi-guard/provision")
async def provision(req: ProvisionRequest):
    license_key = req.provisioning_token.strip().upper()
    if not KEY_PATTERN.fullmatch(license_key):
        raise HTTPException(
            400,
            "Invalid KeyGate key. Expected KG-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX.",
        )

    link = by_key(license_key)
    if not link:
        raise HTTPException(
            403,
            "This key was not issued by the Multi-Servis license portal.",
        )
    if (
        link.get("installation_id")
        and link["installation_id"] != req.installation_id
    ):
        raise HTTPException(
            409,
            "License is already bound to another installation; service rebind required.",
        )
    if link.get("device_id") and link["device_id"] != req.device_id:
        raise HTTPException(
            409,
            "License is already bound to another computer; service rebind required.",
        )

    activated = await keygate.activate(
        license_key=license_key,
        device_id=req.device_id,
        installation_id=req.installation_id,
    )
    returned_license_id = str(activated.get("license_id", ""))
    if returned_license_id != link["keygate_license_id"]:
        raise HTTPException(409, "KeyGate returned a different license mapping.")

    credential = secrets.token_urlsafe(48)
    update_link(
        link["keygate_license_id"],
        installation_id=req.installation_id,
        device_id=req.device_id,
        credential_hash=hash_secret(credential),
        app_version=req.app_version,
        lifecycle="SERVICE_TEST",
        provisioned_at=utcnow(),
    )
    link = by_license(link["keygate_license_id"])

    return {
        "requestId": req.request_id,
        "signedLicense": signed_envelope(link),
        "installationCredential": credential,
        "requiredDocuments": [],
    }


@app.post("/v1/multi-guard/refresh")
async def refresh(req: RefreshRequest):
    link = authenticate_installation(req)
    link = await refresh_lifecycle(link)
    update_link(link["keygate_license_id"], app_version=req.app_version)
    link = by_license(link["keygate_license_id"])

    documents = (
        load_required_documents()
        if link["lifecycle"] == "PENDING_ACCEPTANCE"
        else []
    )
    return {
        "requestId": req.request_id,
        "signedLicense": signed_envelope(link),
        "requiredDocuments": documents,
    }


@app.post("/v1/multi-guard/acceptance")
async def acceptance(req: AcceptanceRequest):
    link = authenticate_installation(req)
    if link["lifecycle"] != "PENDING_ACCEPTANCE":
        raise HTTPException(409, "License is not awaiting customer acceptance.")

    required = load_required_documents()
    if len(required) != 3:
        raise HTTPException(
            503,
            "Exactly three production acceptance documents must be configured.",
        )

    expected = {
        (item["kind"], item["version"], item["sha256"].lower())
        for item in required
    }
    received = {
        (item.kind, item.version, item.sha256.lower())
        for item in req.documents
    }
    if received != expected:
        raise HTTPException(
            400,
            "Accepted documents do not match the current required set.",
        )

    started = utcnow()
    valid_until = started + relativedelta(months=link["duration_months"])
    await keygate.set_valid_until(
        link["keygate_license_id"],
        iso(valid_until),
    )

    update_link(
        link["keygate_license_id"],
        lifecycle="ACTIVE",
        accepted_at=started,
        valid_from=started,
        valid_until=valid_until,
        accepted_documents=[item.model_dump() for item in req.documents],
        app_version=req.app_version,
    )
    link = by_license(link["keygate_license_id"])

    return {
        "requestId": req.request_id,
        "signedLicense": signed_envelope(link),
    }


@app.post(
    "/v1/service/receptions/approve",
    dependencies=[Depends(require_service_token)],
)
def approve_reception(req: ApproveRequest):
    reception_number = req.reception_number.strip()
    link = by_reception(reception_number)
    if not link:
        raise HTTPException(
            404,
            "No Multi-Guard license is linked to this reception.",
        )
    if not link.get("installation_id"):
        raise HTTPException(
            409,
            "Multi-Guard has not yet been installed/provisioned on this computer.",
        )
    if link["lifecycle"] == "ACTIVE":
        return {
            "status": "already_active",
            "reception_number": reception_number,
        }
    if link["lifecycle"] in {"REVOKED", "EXPIRED"}:
        raise HTTPException(
            409,
            f"Cannot approve license from state {link['lifecycle']}.",
        )

    update_link(
        link["keygate_license_id"],
        lifecycle="PENDING_ACCEPTANCE",
        approved_at=utcnow(),
    )
    return {
        "status": "PENDING_ACCEPTANCE",
        "reception_number": reception_number,
    }


@app.get(
    "/v1/service/receptions/{reception_number}/status",
    dependencies=[Depends(require_service_token)],
)
def reception_status(reception_number: str):
    link = by_reception(reception_number.strip())
    if not link:
        return {
            "installed": False,
            "reception_number": reception_number,
        }

    return {
        "installed": bool(link.get("installation_id")),
        "reception_number": link["reception_number"],
        "license_id": link["keygate_license_id"],
        "edition": plan_label(link["plan_code"]),
        "plan_code": link["plan_code"],
        "duration_months": link["duration_months"],
        "lifecycle": link["lifecycle"],
        "app_version": link.get("app_version") or "",
        "valid_from": iso(link.get("valid_from")),
        "valid_until": iso(link.get("valid_until")),
    }


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    error = request.query_params.get("error") == "1"
    message = (
        "<div class='error'>Nieprawidłowy login lub hasło.</div>"
        if error
        else ""
    )
    return page(
        "Logowanie",
        f"""
        <section class="card narrow">
          <h1>Multi-Servis KeyGate</h1>
          <p>Panel serwisowy licencji Multi-Guard</p>
          {message}
          <form method="post" action="/login">
            <label>Login<input name="username" autocomplete="username" required></label>
            <label>Hasło<input type="password" name="password" autocomplete="current-password" required></label>
            <button>Zaloguj</button>
          </form>
        </section>
        """,
    )


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not (
        secrets.compare_digest(username, settings.admin_user)
        and secrets.compare_digest(password, settings.admin_password)
    ):
        return RedirectResponse("/login?error=1", status_code=303)
    request.session.clear()
    request.session["admin"] = True
    return RedirectResponse("/admin", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if request.session.get("admin") is not True:
        return RedirectResponse("/login", status_code=303)

    rows = []
    for item in list_recent(30):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['reception_number'])}</td>"
            f"<td>{html.escape(plan_label(item['plan_code']))}</td>"
            f"<td>{item['duration_months']} mies.</td>"
            f"<td><code>{html.escape(item['lifecycle'])}</code></td>"
            f"<td>{html.escape(item.get('app_version') or '—')}</td>"
            "<td>"
            "<form method='post' action='/admin/reveal'>"
            f"<input type='hidden' name='license_id' value='{html.escape(item['keygate_license_id'])}'>"
            "<button class='secondary'>Pokaż klucz</button>"
            "</form>"
            "</td>"
            "</tr>"
        )
    rows_html = "".join(rows) or "<tr><td colspan='6'>Brak licencji.</td></tr>"

    return page(
        "Panel licencji",
        f"""
        <header>
          <div><strong>Multi-Servis KeyGate</strong><span>Licencje Multi-Guard</span></div>
          <form method="post" action="/logout"><button class="secondary">Wyloguj</button></form>
        </header>
        <main>
          <section class="card">
            <h2>Nowa licencja</h2>
            <p>Generowanie i SERVICE_TEST nie uruchamiają płatnego okresu.</p>
            <form class="grid" method="post" action="/admin/generate">
              <label>Nr zlecenia Multi-Servis
                <input name="reception_number" placeholder="np. MS-2026-00123" required>
              </label>
              <label>Wersja
                <select name="edition">
                  <option value="STANDARD">Multi-Guard</option>
                  <option value="PRO">Multi-Guard Pro</option>
                </select>
              </label>
              <label>Okres
                <select name="months">
                  <option value="3">3 miesiące</option>
                  <option value="6">6 miesięcy</option>
                  <option value="12">12 miesięcy</option>
                </select>
              </label>
              <button>Generuj klucz</button>
            </form>
          </section>
          <section class="card">
            <h2>Ostatnie licencje</h2>
            <div class="table"><table>
              <thead><tr><th>Zlecenie</th><th>Wersja</th><th>Okres</th><th>Stan</th><th>App</th><th></th></tr></thead>
              <tbody>{rows_html}</tbody>
            </table></div>
          </section>
        </main>
        """,
    )


@app.post("/admin/generate", response_class=HTMLResponse)
async def admin_generate(
    request: Request,
    reception_number: str = Form(...),
    edition: str = Form(...),
    months: int = Form(...),
):
    require_admin(request)
    reception_number = reception_number.strip()
    edition = edition.strip().upper()

    if not reception_number:
        raise HTTPException(400, "Reception number is required.")
    if edition not in {"STANDARD", "PRO"} or months not in {3, 6, 12}:
        raise HTTPException(400, "Unsupported Multi-Guard plan.")
    if by_reception(reception_number):
        raise HTTPException(
            409,
            "This Multi-Servis reception already has a Multi-Guard license.",
        )

    plan_slug = settings.plan_slug(edition, months)
    plan = keygate_plan_by_slug(plan_slug)
    if not plan or not plan.get("active"):
        raise HTTPException(
            500,
            f"Configured KeyGate plan not found or inactive: {plan_slug}",
        )
    created = await keygate.create_license(
        plan=plan,
        reception_number=reception_number,
    )
    license_id = str(created.get("id", ""))
    license_key = str(created.get("license_key", ""))
    if not license_id or not license_key:
        raise HTTPException(502, "KeyGate did not return the new license key.")

    create_link(
        license_id=license_id,
        reception_number=reception_number,
        plan_id=str(plan["id"]),
        license_key=license_key,
        plan_code="multi_guard_pro" if edition == "PRO" else "multi_guard",
        duration_months=months,
    )
    return generated_page(
        reception_number,
        edition,
        months,
        license_id,
        license_key,
    )


@app.post("/admin/reveal", response_class=HTMLResponse)
async def admin_reveal(
    request: Request,
    license_id: str = Form(...),
):
    require_admin(request)
    link = by_license(license_id)
    if not link:
        raise HTTPException(404, "License not found.")
    license_key = await keygate.reveal_key(license_id)
    edition = "PRO" if link["plan_code"] == "multi_guard_pro" else "STANDARD"
    return generated_page(
        link["reception_number"],
        edition,
        link["duration_months"],
        license_id,
        license_key,
    )


def generated_page(
    reception_number: str,
    edition: str,
    months: int,
    license_id: str,
    license_key: str,
):
    label = "Multi-Guard Pro" if edition == "PRO" else "Multi-Guard"
    return page(
        "Klucz gotowy",
        f"""
        <section class="card narrow key">
          <h1>Klucz gotowy</h1>
          <p>{html.escape(label)} • {months} mies. • zlecenie {html.escape(reception_number)}</p>
          <code id="license-key">{html.escape(license_key)}</code>
          <button onclick="navigator.clipboard.writeText(document.getElementById('license-key').innerText)">Kopiuj klucz</button>
          <p class="hint">Wklej klucz do Multi-Guard na komputerze klienta. Program przejdzie do SERVICE_TEST. Czas licencji jeszcze nie biegnie.</p>
          <a href="/admin">← Wróć do panelu</a>
          <small>ID: {html.escape(license_id)}</small>
        </section>
        """,
    )


def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} — Multi-Servis KeyGate</title>
<style>
:root{{font-family:Inter,Segoe UI,Arial,sans-serif;color:#edf6ff;background:#06101f}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;background:radial-gradient(circle at 70% 10%,#10345a 0,transparent 35%),#06101f}}
header{{display:flex;justify-content:space-between;align-items:center;padding:18px 28px;border-bottom:1px solid #1e3954;background:#071426}}
header strong,header span{{display:block}}header span{{font-size:12px;color:#8fa9c1;margin-top:3px}}
main{{width:min(1100px,94vw);margin:28px auto;display:grid;gap:18px}}
.card{{background:linear-gradient(145deg,#0c1c31,#081321);border:1px solid #23425f;border-radius:18px;padding:22px;box-shadow:0 24px 70px #0007}}
.narrow{{width:min(520px,92vw);margin:12vh auto}}.card h1,.card h2{{margin:0 0 8px}}.card p{{color:#9fb4c8;line-height:1.5}}
form{{display:grid;gap:12px}}label{{display:grid;gap:6px;font-size:12px;color:#bdd0e1}}
input,select{{width:100%;padding:11px 12px;border:1px solid #2d5677;border-radius:9px;background:#07182a;color:#eef7ff;outline:none}}
button{{border:0;border-radius:9px;padding:11px 15px;background:#139ce7;color:white;font-weight:700;cursor:pointer}}
.secondary{{background:#10263a;color:#c7d8e7;border:1px solid #2a4a66}}
.grid{{grid-template-columns:2fr 1fr 1fr auto;align-items:end}}.table{{overflow:auto}}table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{text-align:left;padding:10px;border-bottom:1px solid #173149}}th{{color:#83a2bd}}td code{{color:#68d9ff}}
.error{{padding:10px;border:1px solid #8d3d49;background:#471923;color:#ffd5da;border-radius:8px;margin:12px 0}}
.key{{display:grid;gap:14px}}.key>code{{display:block;padding:15px;background:#03101c;border:1px solid #24618c;border-radius:10px;color:#67e5ff;font-size:15px;word-break:break-all}}
.key a{{color:#67c8ff}}.key small{{color:#657f96}}.hint{{font-size:12px}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}header{{padding:14px 18px}}}}
</style>
</head>
<body>{body}</body>
</html>"""
