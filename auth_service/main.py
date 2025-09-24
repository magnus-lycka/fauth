"""FastAPI entry point for the authentication service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings
from .models import (
    JWKSKey,
    JWKSResponse,
    LoginForm,
    LogoutRequest,
    RefreshRequest,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    TokenResponse,
    UserInfo,
)
from .security import IssuedTokens, TokenManager
from .token_store import RefreshTokenData, RefreshTokenStore
from .users import CognitoUserBackend, TomlUserBackend, UserIdentityBackend, UserRecord

settings = get_settings()

app = FastAPI(title="fauth authentication service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_token_manager = TokenManager(
    private_key=settings.read_private_key(),
    public_key=settings.read_public_key(),
    issuer=settings.issuer,
    audience=settings.audience,
    access_token_ttl=timedelta(minutes=settings.access_token_exp_minutes),
    refresh_token_ttl=timedelta(minutes=settings.refresh_token_exp_minutes),
)
_refresh_store = RefreshTokenStore()
_http_bearer = HTTPBearer(auto_error=False)
_backend: UserIdentityBackend

if settings.backend == "toml":
    _backend = TomlUserBackend(settings.user_toml_path)
else:
    _backend = CognitoUserBackend(
        user_pool_id=settings.cognito_user_pool_id or "",
        client_id=settings.cognito_client_id or "",
        region=settings.cognito_region or "",
    )

LOGIN_FORM_HTML = """
<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Login</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; }
      form { display: flex; flex-direction: column; gap: 0.5rem; max-width: 20rem; }
      label { display: flex; flex-direction: column; font-weight: 600; }
      input[type=\"submit\"] { margin-top: 1rem; padding: 0.5rem; }
      .error { color: #b00020; }
    </style>
  </head>
  <body>
    <h1>Sign in</h1>
    <form method=\"post\" action=\"/login\">
      <label>Username<input name=\"username\" required /></label>
      <label>Password<input type=\"password\" name=\"password\" required /></label>
      <input type=\"submit\" value=\"Login\" />
    </form>
  </body>
</html>
"""


@app.get("/login", response_class=HTMLResponse)
async def login_form() -> str:
    """Serve a simple HTML form to collect user credentials."""

    return LOGIN_FORM_HTML


@app.post("/login", response_model=TokenResponse)
async def login(request: Request, response: Response) -> TokenResponse:
    """Authenticate a user and mint access and refresh tokens."""

    form = await _parse_login(request)
    user = _backend.authenticate(form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    tokens = _token_manager.issue_tokens(subject=user.username, scopes=user.scopes or [])
    _store_refresh_token(tokens, user.username, user.scopes or [])
    _set_auth_cookies(response, tokens)
    return _token_response(tokens, user)


@app.post("/token/refresh", response_model=TokenResponse)
async def refresh_tokens(
    request: Request,
    response: Response,
    payload: RefreshRequest | None = None,
) -> TokenResponse:
    """Rotate refresh tokens and issue a new access token."""

    provided = payload.refresh_token if payload else None
    refresh_token = _extract_refresh_token(request, provided)
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token missing")
    try:
        refresh_payload = _token_manager.decode_refresh_token(refresh_token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from None
    stored = _refresh_store.get(refresh_token)
    if not stored or stored.subject != refresh_payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")
    user = _backend.get_user(refresh_payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    tokens = _token_manager.issue_tokens(subject=user.username, scopes=user.scopes or [])
    _refresh_store.replace(
        refresh_token,
        tokens.refresh_token,
        RefreshTokenData(
            subject=user.username,
            expires_at=tokens.refresh_expires_at,
            scopes=list(user.scopes or []),
            jti=tokens.refresh_jti,
        ),
    )
    _set_auth_cookies(response, tokens)
    return _token_response(tokens, user)


@app.post("/logout")
async def logout(request: Request, response: Response, payload: LogoutRequest | None = None) -> dict[str, str]:
    """Revoke a refresh token and clear authentication cookies."""

    provided = payload.refresh_token if payload else None
    refresh_token = _extract_refresh_token(request, provided)
    if refresh_token:
        _refresh_store.pop(refresh_token)
    _clear_auth_cookies(response)
    return {"detail": "logged out"}


@app.post("/token/introspect", response_model=TokenIntrospectionResponse)
async def introspect_token(
    payload: TokenIntrospectionRequest,
    api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> TokenIntrospectionResponse:
    """Validate an access token for downstream services."""

    if not api_key or api_key not in settings.introspection_api_keys:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Introspection not allowed")
    try:
        token_payload = _token_manager.decode_access_token(payload.token)
    except jwt.PyJWTError:
        return TokenIntrospectionResponse(active=False)
    return TokenIntrospectionResponse(
        active=True,
        scope=token_payload.get("scope"),
        sub=token_payload.get("sub"),
        exp=token_payload.get("exp"),
        iat=token_payload.get("iat"),
        iss=token_payload.get("iss"),
        aud=token_payload.get("aud"),
        token_type="access",
    )


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
async def jwks() -> JWKSResponse:
    """Expose the public keys required to validate tokens."""

    key = _token_manager.jwk()
    return JWKSResponse(keys=[JWKSKey(**key)])


async def _current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_http_bearer),
) -> UserInfo:
    return _require_user(credentials)


@app.get("/me", response_model=UserInfo)
async def me(current_user: UserInfo = Depends(_current_user)) -> UserInfo:
    """Return details about the currently authenticated user."""

    return current_user


def _require_user(credentials: Optional[HTTPAuthorizationCredentials]) -> UserInfo:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    token = credentials.credentials
    try:
        payload = _token_manager.decode_access_token(token)
    except jwt.PyJWTError as exc:  # pragma: no cover - invalid tokens tested elsewhere
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user = _backend.get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return UserInfo(**user.to_public())


async def _parse_login(request: Request) -> LoginForm:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()
    else:
        form = await request.form()
        payload = {"username": form.get("username"), "password": form.get("password")}
    try:
        return LoginForm(**payload)
    except Exception as exc:  # pragma: no cover - pydantic already validates
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payload") from exc


def _token_response(tokens: IssuedTokens, user: UserRecord) -> TokenResponse:
    now = datetime.now(timezone.utc)
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=int((tokens.access_expires_at - now).total_seconds()),
        refresh_expires_in=int((tokens.refresh_expires_at - now).total_seconds()),
        user=UserInfo(**user.to_public()),
    )


def _store_refresh_token(tokens: IssuedTokens, username: str, scopes: list[str]) -> None:
    _refresh_store.put(
        tokens.refresh_token,
        RefreshTokenData(
            subject=username,
            expires_at=tokens.refresh_expires_at,
            scopes=list(scopes),
            jti=tokens.refresh_jti,
        ),
    )


def _set_auth_cookies(response: Response, tokens: IssuedTokens) -> None:
    now = datetime.now(timezone.utc)
    access_max_age = int((tokens.access_expires_at - now).total_seconds())
    refresh_max_age = int((tokens.refresh_expires_at - now).total_seconds())
    response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        max_age=access_max_age,
        httponly=True,
        secure=settings.cookie_secure_default,
        samesite="lax",
        domain=settings.cookie_domain,
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        max_age=refresh_max_age,
        httponly=True,
        secure=settings.cookie_secure_default,
        samesite="strict",
        domain=settings.cookie_domain,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        "access_token",
        domain=settings.cookie_domain,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        "refresh_token",
        domain=settings.cookie_domain,
        httponly=True,
        samesite="strict",
    )


def _extract_refresh_token(request: Request, provided: str | None) -> str | None:
    if provided:
        return provided
    if "refresh_token" in request.cookies:
        return request.cookies["refresh_token"]
    return None
