"""User identity backends for the authentication service."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Protocol

import boto3
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass(slots=True)
class UserRecord:
    """Internal representation of a user account."""

    username: str
    password_hash: str
    full_name: str | None = None
    email: str | None = None
    scopes: list[str] | None = None

    def to_public(self) -> dict[str, object | None]:
        return {
            "username": self.username,
            "full_name": self.full_name,
            "email": self.email,
            "scopes": list(self.scopes or []),
        }


class UserIdentityBackend(Protocol):
    """Interface implemented by user data sources."""

    def authenticate(self, username: str, password: str) -> UserRecord | None:
        raise NotImplementedError

    def get_user(self, username: str) -> UserRecord | None:
        raise NotImplementedError


class TomlUserBackend:
    """Development backend that reads users from a TOML file."""

    def __init__(self, path: Path) -> None:
        import tomllib

        self._path = path
        if not self._path.exists():
            raise FileNotFoundError(f"User configuration file not found: {self._path}")
        raw = tomllib.loads(self._path.read_text(encoding="utf-8"))
        self._users: Dict[str, UserRecord] = {}
        for entry in raw.get("users", []):
            record = UserRecord(
                username=entry["username"],
                password_hash=entry["password_hash"],
                full_name=entry.get("full_name"),
                email=entry.get("email"),
                scopes=entry.get("scopes", []),
            )
            self._users[record.username] = record

    def authenticate(self, username: str, password: str) -> UserRecord | None:
        user = self._users.get(username)
        if not user:
            return None
        if not pwd_context.verify(password, user.password_hash):
            return None
        return user

    def get_user(self, username: str) -> UserRecord | None:
        return self._users.get(username)


class CognitoUserBackend:
    """Production backend that proxies authentication to AWS Cognito."""

    def __init__(self, *, user_pool_id: str, client_id: str, region: str) -> None:
        if not all([user_pool_id, client_id, region]):
            raise ValueError("Cognito backend requires pool id, client id, and region")
        self._user_pool_id = user_pool_id
        self._client_id = client_id
        self._client = boto3.client("cognito-idp", region_name=region)

    def authenticate(self, username: str, password: str) -> UserRecord | None:
        try:
            self._client.admin_initiate_auth(
                UserPoolId=self._user_pool_id,
                ClientId=self._client_id,
                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password},
            )
        except self._client.exceptions.NotAuthorizedException:
            return None
        except self._client.exceptions.UserNotFoundException:
            return None
        except Exception:  # pragma: no cover - network failures, etc.
            logger.exception("Failed to authenticate against Cognito")
            return None
        return self.get_user(username)

    def get_user(self, username: str) -> UserRecord | None:
        try:
            response = self._client.admin_get_user(
                UserPoolId=self._user_pool_id,
                Username=username,
            )
        except self._client.exceptions.UserNotFoundException:
            return None
        except Exception:  # pragma: no cover - network failures, etc.
            logger.exception("Failed to retrieve Cognito user")
            return None
        attributes = {
            item["Name"]: item["Value"] for item in response.get("UserAttributes", [])
        }
        scopes: list[str] | None = None
        scope_raw = attributes.get("custom:scopes")
        if scope_raw:
            scopes = [scope.strip() for scope in scope_raw.split(",") if scope.strip()]
        return UserRecord(
            username=username,
            password_hash="",
            full_name=attributes.get("name"),
            email=attributes.get("email"),
            scopes=scopes or ["user"],
        )
