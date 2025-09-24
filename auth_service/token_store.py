"""In-memory refresh token store."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Dict, Iterable


@dataclass(slots=True)
class RefreshTokenData:
    """Metadata stored alongside a refresh token."""

    subject: str
    expires_at: datetime
    scopes: list[str]
    jti: str


class RefreshTokenStore:
    """Simple in-memory refresh token registry."""

    def __init__(self) -> None:
        self._tokens: Dict[str, RefreshTokenData] = {}
        self._lock = RLock()

    @staticmethod
    def _hash(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def put(self, raw_token: str, data: RefreshTokenData) -> None:
        hashed = self._hash(raw_token)
        with self._lock:
            self._tokens[hashed] = data

    def pop(self, raw_token: str) -> RefreshTokenData | None:
        hashed = self._hash(raw_token)
        with self._lock:
            return self._tokens.pop(hashed, None)

    def get(self, raw_token: str) -> RefreshTokenData | None:
        hashed = self._hash(raw_token)
        with self._lock:
            data = self._tokens.get(hashed)
            if not data:
                return None
            if data.expires_at <= datetime.now(timezone.utc):
                self._tokens.pop(hashed, None)
                return None
            return data

    def replace(self, old_token: str, new_token: str, data: RefreshTokenData) -> None:
        new_hashed = self._hash(new_token)
        old_hashed = self._hash(old_token)
        with self._lock:
            self._tokens.pop(old_hashed, None)
            self._tokens[new_hashed] = data

    def revoke_subject(self, subject: str) -> None:
        with self._lock:
            expired: list[str] = [
                token_hash
                for token_hash, data in self._tokens.items()
                if data.subject == subject
            ]
            for token_hash in expired:
                self._tokens.pop(token_hash, None)

    def cleanup(self) -> None:
        """Remove expired tokens."""

        with self._lock:
            expired: Iterable[str] = [
                token_hash
                for token_hash, data in self._tokens.items()
                if data.expires_at <= datetime.now(timezone.utc)
            ]
            for token_hash in expired:
                self._tokens.pop(token_hash, None)
