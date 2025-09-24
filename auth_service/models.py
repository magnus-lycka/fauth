"""Pydantic models shared by the authentication service."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserInfo(BaseModel):
    """Publicly exposed information about an authenticated user."""

    username: str
    full_name: str | None = None
    email: EmailStr | None = None
    scopes: list[str] = Field(default_factory=list)


class TokenResponse(BaseModel):
    """Response body containing freshly issued tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int
    user: UserInfo


class RefreshRequest(BaseModel):
    """Request payload to refresh access credentials."""

    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    """Request payload to revoke a refresh token."""

    refresh_token: str | None = None


class TokenIntrospectionRequest(BaseModel):
    """Request to introspect the validity of an access token."""

    token: str


class TokenIntrospectionResponse(BaseModel):
    """RFC 7662 compatible token introspection response."""

    active: bool
    scope: str | None = None
    sub: str | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None
    aud: str | None = None
    token_type: str | None = None


class JWKSKey(BaseModel):
    """Minimal JSON Web Key structure."""

    kty: str
    kid: str
    use: str
    alg: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    """JWKS endpoint response."""

    keys: list[JWKSKey]


class TokenPayload(BaseModel):
    """Representation of an access token payload used by downstream services."""

    sub: str
    scope: str | None = None
    iss: str
    aud: str
    exp: datetime
    iat: datetime
    jti: str
    token_type: str


class LoginForm(BaseModel):
    """Model used to parse login submissions from JSON or form data."""

    username: str
    password: str
