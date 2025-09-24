"""Security helpers for issuing and validating JWT tokens."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


@dataclass(slots=True)
class IssuedTokens:
    """Aggregate information about newly issued credentials."""

    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    access_jti: str
    refresh_jti: str


class TokenManager:
    """Create and verify JWT access/refresh tokens."""

    algorithm = "RS256"

    def __init__(
        self,
        *,
        private_key: str,
        public_key: str,
        issuer: str,
        audience: str,
        access_token_ttl: timedelta,
        refresh_token_ttl: timedelta,
    ) -> None:
        self._private_key = private_key
        self._public_key = public_key
        self._issuer = issuer
        self._audience = audience
        self._access_token_ttl = access_token_ttl
        self._refresh_token_ttl = refresh_token_ttl
        self._kid = self._compute_kid(public_key)

    @staticmethod
    def _compute_kid(public_key: str) -> str:
        raw = public_key.encode("utf-8")
        digest = hashlib.sha1(raw).digest()
        return base64.urlsafe_b64encode(digest[:8]).decode("ascii").rstrip("=")

    def issue_tokens(self, *, subject: str, scopes: list[str]) -> IssuedTokens:
        access_token, access_exp, access_jti = self._create_token(
            subject=subject,
            scopes=scopes,
            ttl=self._access_token_ttl,
            token_type="access",
        )
        refresh_token, refresh_exp, refresh_jti = self._create_token(
            subject=subject,
            scopes=scopes,
            ttl=self._refresh_token_ttl,
            token_type="refresh",
        )
        return IssuedTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_exp,
            refresh_expires_at=refresh_exp,
            access_jti=access_jti,
            refresh_jti=refresh_jti,
        )

    def _create_token(
        self,
        *,
        subject: str,
        scopes: list[str],
        ttl: timedelta,
        token_type: str,
    ) -> tuple[str, datetime, str]:
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + ttl
        jti = secrets.token_urlsafe(32)
        payload = {
            "sub": subject,
            "scope": " ".join(scopes),
            "iss": self._issuer,
            "aud": self._audience,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": jti,
            "token_type": token_type,
        }
        headers = {"kid": self._kid}
        token = jwt.encode(payload, self._private_key, algorithm=self.algorithm, headers=headers)
        return token, expires_at, jti

    def decode(self, token: str, *, verify_exp: bool = True) -> Dict[str, Any]:
        return jwt.decode(
            token,
            self._public_key,
            algorithms=[self.algorithm],
            audience=self._audience,
            issuer=self._issuer,
            options={"verify_exp": verify_exp},
        )

    def decode_access_token(self, token: str) -> Dict[str, Any]:
        payload = self.decode(token)
        if payload.get("token_type") != "access":
            raise jwt.InvalidTokenError("Token is not an access token")
        return payload

    def decode_refresh_token(self, token: str) -> Dict[str, Any]:
        payload = self.decode(token)
        if payload.get("token_type") != "refresh":
            raise jwt.InvalidTokenError("Token is not a refresh token")
        return payload

    def jwk(self) -> Dict[str, str]:
        public_key = serialization.load_pem_public_key(self._public_key.encode("utf-8"))
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("Public key must be RSA")
        numbers = public_key.public_numbers()
        n = self._int_to_base64(numbers.n)
        e = self._int_to_base64(numbers.e)
        return {
            "kty": "RSA",
            "kid": self._kid,
            "use": "sig",
            "alg": self.algorithm,
            "n": n,
            "e": e,
        }

    @staticmethod
    def _int_to_base64(value: int) -> str:
        byte_length = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).decode("ascii").rstrip("=")
