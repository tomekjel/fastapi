from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str
    keygate_base_url: str
    keygate_licenses_token: str
    admin_user: str
    admin_password: str
    session_secret: str
    service_token: str
    signing_seed_b64: str
    public_base_url: str
    license_email: str

    @classmethod
    def from_env(cls) -> "Settings":
        value = cls(
            database_url=os.getenv("BRIDGE_DATABASE_URL", "").strip(),
            keygate_base_url=os.getenv("KEYGATE_BASE_URL", "http://keygate:9000").strip().rstrip("/"),
            keygate_licenses_token=os.getenv("KEYGATE_LICENSES_TOKEN", "").strip(),
            admin_user=os.getenv("BRIDGE_ADMIN_USER", "admin").strip() or "admin",
            admin_password=os.getenv("BRIDGE_ADMIN_PASSWORD", "").strip(),
            session_secret=os.getenv("BRIDGE_SESSION_SECRET", "").strip(),
            service_token=os.getenv("BRIDGE_SERVICE_TOKEN", "").strip(),
            signing_seed_b64=os.getenv("BRIDGE_SIGNING_SEED_B64", "").strip(),
            public_base_url=os.getenv("BRIDGE_PUBLIC_BASE_URL", "").strip().rstrip("/"),
            license_email=os.getenv("BRIDGE_LICENSE_EMAIL", "licencje@multi-servis.pl").strip(),
        )
        value.validate()
        return value

    def validate(self) -> None:
        required = {
            "BRIDGE_DATABASE_URL": self.database_url,
            "KEYGATE_LICENSES_TOKEN": self.keygate_licenses_token,
            "BRIDGE_ADMIN_PASSWORD": self.admin_password,
            "BRIDGE_SESSION_SECRET": self.session_secret,
            "BRIDGE_SERVICE_TOKEN": self.service_token,
            "BRIDGE_SIGNING_SEED_B64": self.signing_seed_b64,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError("Missing required settings: " + ", ".join(missing))

    def plan_slug(self, edition: str, months: int) -> str:
        edition = edition.upper()
        defaults = {
            ("STANDARD", 3): "multi-guard-assist-3m",
            ("STANDARD", 6): "multi-guard-assist-6m",
            ("STANDARD", 12): "multi-guard-assist-12m",
            ("PRO", 3): "multi-guard-assist-pro-3m",
            ("PRO", 6): "multi-guard-assist-pro-6m",
            ("PRO", 12): "multi-guard-assist-pro-12m",
        }
        env_names = {
            ("STANDARD", 3): "BRIDGE_PLAN_STANDARD_3M",
            ("STANDARD", 6): "BRIDGE_PLAN_STANDARD_6M",
            ("STANDARD", 12): "BRIDGE_PLAN_STANDARD_12M",
            ("PRO", 3): "BRIDGE_PLAN_PRO_3M",
            ("PRO", 6): "BRIDGE_PLAN_PRO_6M",
            ("PRO", 12): "BRIDGE_PLAN_PRO_12M",
        }
        key = (edition, months)
        if key not in defaults:
            raise ValueError("Unsupported Multi-Guard plan")
        return os.getenv(env_names[key], defaults[key]).strip()


settings = Settings.from_env()
