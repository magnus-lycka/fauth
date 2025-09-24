from __future__ import annotations

import os

os.environ.setdefault("PROTECTED_VERIFICATION_MODE", "shared")

from fastapi.testclient import TestClient

import auth_service.main as auth_main
import protected_service.main as protected_main


def reset_refresh_store() -> None:
    for username in ("alice", "bob"):
        auth_main._refresh_store.revoke_subject(username)


def test_login_refresh_logout_cycle() -> None:
    reset_refresh_store()
    client = TestClient(auth_main.app)

    response = client.post("/login", json={"username": "alice", "password": "wonderland123"})
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body

    me_response = client.get("/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me_response.status_code == 200
    assert me_response.json()["username"] == "alice"

    refresh_response = client.post("/token/refresh", json={})
    assert refresh_response.status_code == 200
    new_body = refresh_response.json()
    assert new_body["access_token"] != body["access_token"]

    logout_response = client.post("/logout", json={})
    assert logout_response.status_code == 200
    assert client.cookies.get("refresh_token") is None

    failed_refresh = client.post("/token/refresh", json={})
    assert failed_refresh.status_code == 401


def test_protected_api_requires_authentication() -> None:
    reset_refresh_store()
    auth_client = TestClient(auth_main.app)
    login = auth_client.post("/login", json={"username": "bob", "password": "builder123"})
    assert login.status_code == 200
    token = login.json()["access_token"]

    protected_client = TestClient(protected_main.app)
    unauthenticated = protected_client.get("/api/secret")
    assert unauthenticated.status_code == 401

    authenticated = protected_client.get(
        "/api/secret",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert authenticated.status_code == 200
    payload = authenticated.json()
    assert payload["message"].startswith("Welcome, bob")
