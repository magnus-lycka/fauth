"""Configuration helpers for the authentication service."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the authentication service."""

    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env", extra="ignore")

    environment: Literal["dev", "prod"] = "dev"
    backend: Literal["toml", "cognito"] = "toml"
    user_toml_path: Path = Path("config/users.toml")
    private_key_path: Path = Path("config/private_key.pem")
    public_key_path: Path = Path("config/public_key.pem")
    issuer: str = "fauth-auth"
    audience: str = "fauth-clients"
    access_token_exp_minutes: int = 15
    refresh_token_exp_minutes: int = 60 * 24
    cookie_domain: str | None = None
    cookie_secure: bool | None = None
    allowed_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:8001",
            "http://127.0.0.1:8001",
            "http://localhost:3000",
        ]
    )
    introspection_api_keys: List[str] = Field(default_factory=lambda: ["dev-introspect-key"])

    # AWS Cognito configuration for production deployments
    cognito_user_pool_id: str | None = None
    cognito_client_id: str | None = None
    cognito_region: str | None = None

    @field_validator("allowed_origins", "introspection_api_keys", mode="before")
    @classmethod
    def _split_comma_separated(cls, value: object) -> List[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        return []

    def read_private_key(self) -> str:
        return Path(self.private_key_path).read_text(encoding="utf-8")

    def read_public_key(self) -> str:
        return Path(self.public_key_path).read_text(encoding="utf-8")

    @property
    def cookie_secure_default(self) -> bool:
        """Whether cookies should be marked secure."""

        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.environment == "prod"


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
