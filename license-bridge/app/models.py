from __future__ import annotations

from pydantic import BaseModel, Field


class ProvisionRequest(BaseModel):
    request_id: str = Field(alias="requestId")
    nonce: str
    sent_at: str = Field(alias="sentAt")
    provisioning_token: str = Field(alias="provisioningToken")
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId")
    app_version: str = Field(alias="appVersion")

    model_config = {"populate_by_name": True}


class RefreshRequest(BaseModel):
    request_id: str = Field(alias="requestId")
    nonce: str
    sent_at: str = Field(alias="sentAt")
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId")
    installation_credential: str = Field(alias="installationCredential")
    app_version: str = Field(alias="appVersion")

    model_config = {"populate_by_name": True}


class AcceptedDocument(BaseModel):
    kind: str
    version: str
    sha256: str


class AcceptanceRequest(RefreshRequest):
    documents: list[AcceptedDocument]


class ApproveRequest(BaseModel):
    reception_number: str
