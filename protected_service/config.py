"""Configuration for the protected resource service."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the protected API."""

    model_config = SettingsConfigDict(env_prefix="PROTECTED_", env_file=".env", extra="ignore")

    environment: Literal["dev", "prod"] = "dev"
    verification_mode: Literal["jwks", "introspection", "shared"] = "jwks"
    auth_base_url: str = "http://localhost:8000"
    jwks_url: str | None = None
    jwks_refresh_seconds: int = 300
    shared_public_key_path: Path = Path("config/public_key.pem")
    issuer: str = "fauth-auth"
    audience: str = "fauth-clients"
    introspection_url: str | None = None
    introspection_api_key: str | None = "dev-introspect-key"
    allowed_origins: List[str] = Field(default_factory=lambda: [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://localhost:3000",
    ])
    frontend_directory: Path = Path("frontend")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> List[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        return []

    def resolve_jwks_url(self) -> str:
        if self.jwks_url:
            return self.jwks_url
        return f"{self.auth_base_url.rstrip('/')}/.well-known/jwks.json"

    def resolve_introspection_url(self) -> str:
        if self.introspection_url:
            return self.introspection_url
        return f"{self.auth_base_url.rstrip('/')}/token/introspect"


@lru_cache
def get_settings() -> Settings:
    return Settings()
