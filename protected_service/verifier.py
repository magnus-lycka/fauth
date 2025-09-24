"""Token verification strategies for the protected service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import jwt


class TokenVerificationError(Exception):
    """Raised when a token cannot be validated."""


class TokenVerifier:
    """Base class for token verification strategies."""

    async def verify(self, token: str) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class JWKSCache:
    """Cached JWKS set."""

    keys: dict[str, dict[str, Any]]
    fetched_at: datetime


class JWKSVerifier(TokenVerifier):
    """Validate tokens using the JWKS endpoint from the auth service."""

    def __init__(self, *, jwks_url: str, issuer: str, audience: str, refresh_seconds: int = 300) -> None:
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._refresh_seconds = refresh_seconds
        self._cache: Optional[JWKSCache] = None

    async def verify(self, token: str) -> Dict[str, Any]:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise TokenVerificationError("Token missing key id")
        key = await self._get_key(kid)
        if not key:
            raise TokenVerificationError("Unknown signing key")
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=self._audience,
            issuer=self._issuer,
        )

    async def _get_key(self, kid: str) -> dict[str, Any] | None:
        cache = self._cache
        now = datetime.now(timezone.utc)
        if not cache or (now - cache.fetched_at).total_seconds() > self._refresh_seconds:
            cache = await self._refresh_cache()
        key = cache.keys.get(kid) if cache else None
        if key is None and cache:
            cache = await self._refresh_cache()
            key = cache.keys.get(kid)
        return key

    async def _refresh_cache(self) -> JWKSCache:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(self._jwks_url)
            response.raise_for_status()
        payload = response.json()
        keys = {entry["kid"]: entry for entry in payload.get("keys", [])}
        self._cache = JWKSCache(keys=keys, fetched_at=datetime.now(timezone.utc))
        return self._cache


class SharedKeyVerifier(TokenVerifier):
    """Validate tokens using a locally shared public key."""

    def __init__(self, *, public_key_path: Path, issuer: str, audience: str) -> None:
        self._public_key = public_key_path.read_text(encoding="utf-8")
        self._issuer = issuer
        self._audience = audience

    async def verify(self, token: str) -> Dict[str, Any]:
        return jwt.decode(
            token,
            self._public_key,
            algorithms=["RS256"],
            audience=self._audience,
            issuer=self._issuer,
        )


class IntrospectionVerifier(TokenVerifier):
    """Validate tokens by delegating to the auth service introspection endpoint."""

    def __init__(self, *, url: str, api_key: str | None) -> None:
        self._url = url
        self._api_key = api_key

    async def verify(self, token: str) -> Dict[str, Any]:
        headers = {"X-API-KEY": self._api_key} if self._api_key else {}
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(self._url, json={"token": token}, headers=headers)
        if response.status_code == 403:
            raise TokenVerificationError("Introspection forbidden")
        response.raise_for_status()
        payload = response.json()
        if not payload.get("active"):
            raise TokenVerificationError("Inactive token")
        return {
            "sub": payload.get("sub"),
            "scope": payload.get("scope"),
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "token_type": payload.get("token_type", "access"),
        }
