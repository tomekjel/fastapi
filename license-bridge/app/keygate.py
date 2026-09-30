from __future__ import annotations

from typing import Any

import httpx
from fastapi import HTTPException

from .config import settings


class KeyGateClient:
    async def request(
        self,
        method: str,
        path: str,
        *,
        admin: bool = False,
        body: Any | None = None,
    ) -> Any:
        headers = {"Accept": "application/json"}
        if admin:
            headers["Authorization"] = f"Bearer {settings.keygate_licenses_token}"

        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.request(
                method,
                f"{settings.keygate_base_url}{path}",
                headers=headers,
                json=body,
            )

        try:
            payload = response.json()
        except Exception:
            payload = None

        if not response.is_success:
            detail = payload if payload is not None else response.text[:500]
            raise HTTPException(response.status_code, f"KeyGate error: {detail}")

        if isinstance(payload, dict) and payload.get("success") is False:
            raise HTTPException(502, f"KeyGate rejected request: {payload.get('error')}")

        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    async def create_license(
        self,
        *,
        plan: dict[str, Any],
        reception_number: str,
    ) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/api/v1/admin/licenses",
            admin=True,
            body={
                "product_id": plan["product_id"],
                "plan_id": plan["id"],
                "email": settings.license_email,
                "notes": (
                    f"Multi-Servis reception {reception_number}; "
                    "paid period starts only after customer acceptance."
                ),
                "external_workspace_id": reception_number,
            },
        )

    async def activate(
        self,
        *,
        license_key: str,
        device_id: str,
        installation_id: str,
    ) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/api/v1/license/activate",
            body={
                "license_key": license_key,
                "identifier": device_id,
                "identifier_type": "device",
                "label": f"Multi-Guard {installation_id[:12]}",
            },
        )

    async def get_license(self, license_id: str) -> dict[str, Any]:
        return await self.request(
            "GET",
            f"/api/v1/admin/licenses/{license_id}",
            admin=True,
        )

    async def set_valid_until(self, license_id: str, valid_until: str) -> None:
        await self.request(
            "POST",
            f"/api/v1/admin/licenses/{license_id}/valid-until",
            admin=True,
            body={"valid_until": valid_until},
        )

    async def reveal_key(self, license_id: str) -> str:
        data = await self.request(
            "GET",
            f"/api/v1/admin/licenses/{license_id}/key",
            admin=True,
        )
        if isinstance(data, dict):
            value = data.get("license_key") or data.get("key")
            if value:
                return str(value)
        raise HTTPException(502, "KeyGate did not reveal the license key")


keygate = KeyGateClient()
