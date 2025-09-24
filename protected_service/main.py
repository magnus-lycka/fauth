"""FastAPI application exposing a protected API."""

from __future__ import annotations

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .verifier import (
    IntrospectionVerifier,
    JWKSVerifier,
    SharedKeyVerifier,
    TokenVerificationError,
    TokenVerifier,
)

settings = get_settings()

app = FastAPI(title="fauth protected service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_verifier: TokenVerifier
if settings.verification_mode == "jwks":
    _verifier = JWKSVerifier(
        jwks_url=settings.resolve_jwks_url(),
        issuer=settings.issuer,
        audience=settings.audience,
        refresh_seconds=settings.jwks_refresh_seconds,
    )
elif settings.verification_mode == "introspection":
    _verifier = IntrospectionVerifier(
        url=settings.resolve_introspection_url(),
        api_key=settings.introspection_api_key,
    )
else:
    _verifier = SharedKeyVerifier(
        public_key_path=settings.shared_public_key_path,
        issuer=settings.issuer,
        audience=settings.audience,
    )

_security = HTTPBearer(auto_error=False)
_frontend_path = settings.frontend_directory
if _frontend_path.exists():
    app.mount("/demo", StaticFiles(directory=str(_frontend_path), html=True), name="demo")


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    """Display a landing page for manual testing."""

    if _frontend_path.exists():
        index_file = _frontend_path / "index.html"
        if index_file.exists():
            return HTMLResponse(index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Protected API</h1><p>Use /api/secret with an access token.</p>")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


async def _get_token_payload(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> dict:
    token = credentials.credentials if credentials else request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    try:
        return await _verifier.verify(token)
    except TokenVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


@app.get("/api/secret")
async def read_secret(payload: dict = Depends(_get_token_payload)) -> dict:
    scopes = (payload.get("scope") or "").split()
    return {
        "message": f"Welcome, {payload.get('sub', 'anonymous')}!",
        "scopes": scopes,
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    }


@app.get("/api/profile")
async def profile(payload: dict = Depends(_get_token_payload)) -> dict:
    return {
        "subject": payload.get("sub"),
        "scope": payload.get("scope"),
        "issuer": payload.get("iss"),
        "audience": payload.get("aud"),
    }
