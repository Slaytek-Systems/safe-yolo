from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any


class CapabilityStore:
    """Opaque, expiring capabilities minted only from a trusted prompt hook."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve(strict=False)

    def issue(
        self,
        *,
        kind: str,
        session_id: str,
        constraints: dict[str, Any],
        ttl_seconds: int,
        user_authorized: bool,
        action: str | None = None,
    ) -> str:
        if user_authorized is not True:
            raise PermissionError("Capabilities may only be issued from a trusted user-authorization event.")
        if not session_id or ttl_seconds <= 0:
            raise ValueError("Capabilities require a session and a positive TTL.")

        token = secrets.token_urlsafe(32)
        now = time.time()
        record = {
            "token": token,
            "kind": kind,
            "action": action,
            "session_id": session_id,
            "constraints": constraints,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        }
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        target = self.root / f"{token}.json"
        target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.chmod(target, 0o600)
        return token

    def resolve(self, token: str | None, request: dict[str, Any]) -> dict[str, Any] | None:
        if not token or not all(character.isalnum() or character in "-_" for character in token):
            return None
        target = self.root / f"{token}.json"
        try:
            record = json.loads(target.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        if record.get("token") != token or record.get("revoked_at") or record.get("expires_at", 0) <= time.time():
            return None
        if record.get("session_id") != request.get("session_id"):
            return None
        return record

    def resolve_active(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not self.root.exists() or not request.get("session_id"):
            return None
        candidates = sorted(self.root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for target in candidates:
            token = target.stem
            record = self.resolve(token, request)
            if record is not None:
                return record
        return None

    def revoke_session(self, session_id: str) -> int:
        if not session_id or not self.root.exists():
            return 0
        revoked = 0
        for target in self.root.glob("*.json"):
            try:
                record = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if record.get("session_id") != session_id or record.get("revoked_at"):
                continue
            record["revoked_at"] = time.time()
            target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(target, 0o600)
            revoked += 1
        return revoked


class PendingMaintenanceStore:
    """One-time maintenance requests awaiting an exact user approval prompt."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve(strict=False)

    def _prepare_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def request(
        self,
        *,
        session_id: str,
        harness: str,
        scopes: list[str],
        kind: str = "maintenance",
        ttl_seconds: int = 15 * 60,
    ) -> dict[str, Any]:
        if (
            not session_id
            or not harness
            or not scopes
            or kind not in {"maintenance", "policy_maintenance"}
            or ttl_seconds <= 0
        ):
            raise ValueError("Pending maintenance requires session, harness, scopes, and positive TTL.")
        self._prepare_root()
        now = time.time()
        record = {
            "id": secrets.token_urlsafe(24),
            "session_id": session_id,
            "kind": kind,
            "harness": harness,
            "scopes": sorted(set(scopes)),
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        }
        target = self.root / f"{record['id']}.json"
        target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.chmod(target, 0o600)
        return record

    def consume(self, session_id: str) -> dict[str, Any] | None:
        if not session_id or not self.root.exists():
            return None
        candidates = sorted(self.root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for target in candidates:
            try:
                record = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if (
                record.get("session_id") != session_id
                or record.get("consumed_at")
                or record.get("cancelled_at")
                or record.get("expires_at", 0) <= time.time()
            ):
                continue
            record["consumed_at"] = time.time()
            target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(target, 0o600)
            return record
        return None

    def cancel(self, session_id: str) -> int:
        if not session_id or not self.root.exists():
            return 0
        cancelled = 0
        for target in self.root.glob("*.json"):
            try:
                record = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if record.get("session_id") != session_id or record.get("consumed_at") or record.get("cancelled_at"):
                continue
            record["cancelled_at"] = time.time()
            target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(target, 0o600)
            cancelled += 1
        return cancelled


class PendingActionStore:
    """One-time action requests awaiting an exact user approval prompt."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve(strict=False)

    def _prepare_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def request(
        self,
        *,
        session_id: str,
        action: str,
        constraints: dict[str, Any],
        ttl_seconds: int = 15 * 60,
    ) -> dict[str, Any]:
        if not session_id or not action or not constraints or ttl_seconds <= 0:
            raise ValueError("Pending actions require a session, normalized action, exact constraints, and positive TTL.")
        self._prepare_root()
        now = time.time()
        record = {
            "id": secrets.token_urlsafe(24),
            "session_id": session_id,
            "kind": "action",
            "action": action,
            "constraints": constraints,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
        }
        target = self.root / f"{record['id']}.json"
        target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.chmod(target, 0o600)
        return record

    def consume(self, session_id: str) -> dict[str, Any] | None:
        if not session_id or not self.root.exists():
            return None
        candidates = sorted(self.root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for target in candidates:
            try:
                record = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if (
                record.get("session_id") != session_id
                or record.get("consumed_at")
                or record.get("cancelled_at")
                or record.get("expires_at", 0) <= time.time()
            ):
                continue
            record["consumed_at"] = time.time()
            target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(target, 0o600)
            return record
        return None

    def cancel(self, session_id: str) -> int:
        if not session_id or not self.root.exists():
            return 0
        cancelled = 0
        for target in self.root.glob("*.json"):
            try:
                record = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if record.get("session_id") != session_id or record.get("consumed_at") or record.get("cancelled_at"):
                continue
            record["cancelled_at"] = time.time()
            target.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            os.chmod(target, 0o600)
            cancelled += 1
        return cancelled
