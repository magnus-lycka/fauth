# fauth

A minimal authentication platform for browser-based applications built with FastAPI and JWT. The project ships two cooperative services:

* **Auth service** (`auth_service`) issues and rotates JWT access/refresh tokens, serves a login/logout experience, exposes a JWKS endpoint, and optionally delegates to AWS Cognito in production.
* **Protected service** (`protected_service`) represents a resource server secured by the auth service. It validates incoming requests via shared public keys, JWKS, or the auth service introspection endpoint, and hosts a small JavaScript demo frontend.

Both services target Python 3.13 semantics and run on FastAPI. Development defaults to an in-repo TOML user store and a generated RSA key pair. Production deployments can switch to AWS Cognito and external secret storage through environment variables.

## Repository layout

```
auth_service/          FastAPI auth API and identity integrations
protected_service/     Example protected API and static demo frontend
frontend/              JavaScript single-page demo served by the protected API
config/                Development configuration (users, RSA key pair)
tests/                 Pytest suite covering the auth flow
pyproject.toml         Python dependencies
```

## Getting started

1. **Install dependencies** (inside a Python 3.13 virtual environment if available):

   ```bash
   pip install -e .
   ```

2. **Run the authentication service**:

   ```bash
   uvicorn auth_service.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Run the protected service**:

   ```bash
   uvicorn protected_service.main:app --host 0.0.0.0 --port 8001 --reload
   ```

4. Open `http://localhost:8001/demo` in a browser. The page offers login, refresh, logout, and protected API calls. Development credentials live in `config/users.toml` (e.g. `alice` / `wonderland123`).

## Authentication service

* **Login & logout** – `GET /login` serves an HTML form, `POST /login` accepts JSON or form-encoded credentials, sets secure HttpOnly cookies, and returns JWTs. `POST /logout` revokes the refresh token and clears cookies.
* **Token lifecycle** – Access tokens default to 15 minutes, refresh tokens 24 hours. `POST /token/refresh` rotates tokens and updates cookies. Refresh tokens are stored hashed in memory.
* **User backends** – Development uses the TOML file described above. Set `AUTH_BACKEND=cognito` and the `AUTH_COGNITO_*` variables to forward authentication to AWS Cognito (`admin_initiate_auth`/`admin_get_user`).
* **Federation** – `GET /.well-known/jwks.json` publishes the RSA public key as JWKS. `POST /token/introspect` validates tokens for downstream services and is protected by the `X-API-KEY` header (`AUTH_INTROSPECTION_API_KEYS`).

### Key environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `AUTH_BACKEND` | `toml` or `cognito` user backend | `toml` |
| `AUTH_USER_TOML_PATH` | Path to the TOML user store | `config/users.toml` |
| `AUTH_PRIVATE_KEY_PATH` / `AUTH_PUBLIC_KEY_PATH` | RSA key pair | generated dev keys |
| `AUTH_ACCESS_TOKEN_EXP_MINUTES` | Access token TTL | `15` |
| `AUTH_REFRESH_TOKEN_EXP_MINUTES` | Refresh token TTL | `1440` |
| `AUTH_INTROSPECTION_API_KEYS` | Comma separated API keys for `/token/introspect` | `dev-introspect-key` |

## Protected service

The protected API demonstrates three verification strategies selected via `PROTECTED_VERIFICATION_MODE`:

* `jwks` (default) – fetch the JWKS from the auth service at startup and on a configurable cadence.
* `shared` – load a public key from disk for fully offline validation.
* `introspection` – call the auth service’s introspection endpoint using an API key.

It provides:

* `GET /api/secret` – returns a message when the caller presents a valid JWT.
* `GET /api/profile` – returns token metadata.
* `/demo` – static frontend demonstrating the full flow.

Important environment knobs include `PROTECTED_AUTH_BASE_URL`, `PROTECTED_JWKS_REFRESH_SECONDS`, `PROTECTED_SHARED_PUBLIC_KEY_PATH`, and `PROTECTED_INTROSPECTION_URL`/`PROTECTED_INTROSPECTION_API_KEY`.

## Token structure

Tokens use the RS256 algorithm and carry the following claims:

```
sub, scope, iss, aud, iat, exp, jti, token_type
```

Refresh tokens share the same structure with `token_type="refresh"` and are hashed before storage. The JWKS endpoint exposes the signing key using a deterministic key id (KID) derived from the public key.

## Testing

Run the automated suite:

```bash
pytest
```

The tests exercise login, refresh, logout, and the protected API using the shared-key verification mode.

## Production notes

* Store private keys and Cognito secrets outside the repo (e.g. AWS Secrets Manager) and point the services to them via environment variables.
* Enable HTTPS and set `AUTH_COOKIE_SECURE=true` to force secure cookies.
* When using Cognito, ensure IAM permissions allow the `admin_initiate_auth` and `admin_get_user` calls from the auth service.
* For larger deployments, replace the in-memory refresh token store with a persistent database and add structured logging/metrics as appropriate.
