from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any


APPROVAL_ANSWER = "Approve once (Recommended)"
QUESTION_ID = "safe_yolo_approval"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class ApprovalLedger:
    """Host-local, one-shot approvals bound to an exact tool action."""

    def __init__(self, root: str | Path, *, ttl_seconds: int = 5 * 60) -> None:
        self.root = Path(root).expanduser().resolve(strict=False)
        self.pending = self.root / "pending-v2"
        self.approved = self.root / "approved-v2"
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def action_fingerprint(payload: dict[str, Any]) -> str:
        action = {
            "cwd": str(payload.get("cwd") or ""),
            "tool_input": payload.get("tool_input") or {},
            "tool_name": str(payload.get("tool_name") or "").lower(),
        }
        return _digest(action)

    @staticmethod
    def _scope(payload: dict[str, Any]) -> tuple[str, str]:
        return str(payload.get("session_id") or ""), str(payload.get("turn_id") or "")

    @staticmethod
    def _write(target: Path, record: dict[str, Any]) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(_canonical(record), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    @contextmanager
    def _locked(self):
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        lock_path = self.root / ".approval-v2.lock"
        with lock_path.open("a+", encoding="utf-8") as handle:
            os.chmod(lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _read(target: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def create_request(
        self,
        payload: dict[str, Any],
        *,
        consequence: str,
        display: str,
    ) -> dict[str, Any]:
        session_id, turn_id = self._scope(payload)
        if not session_id or not turn_id:
            raise ValueError("Approval requests require session_id and turn_id.")
        request_id = secrets.token_urlsafe(18)
        fingerprint = self.action_fingerprint(payload)
        question = (
            f"Approve one exact retry for {consequence}: {display}? "
            f"Request {request_id}; action fingerprint {fingerprint}."
        )
        tool_input = {
            "questions": [
                {
                    "header": "Safe YOLO",
                    "id": QUESTION_ID,
                    "question": question,
                    "options": [
                        {
                            "label": APPROVAL_ANSWER,
                            "description": "Permit one identical retry in this task turn.",
                        },
                        {
                            "label": "Reject",
                            "description": "Keep the consequential action blocked.",
                        },
                    ],
                }
            ]
        }
        now = time.time()
        record = {
            "id": request_id,
            "session_id": session_id,
            "turn_id": turn_id,
            "fingerprint": fingerprint,
            "consequence": consequence,
            "approval_input_hash": _digest(tool_input),
            "issued_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        with self._locked():
            self._write(self.pending / f"{request_id}.json", record)
        return tool_input

    @staticmethod
    def _approved_answer(response: Any) -> bool:
        if not isinstance(response, dict):
            return False
        answers = response.get("answers")
        if not isinstance(answers, dict):
            return False
        selected = answers.get(QUESTION_ID)
        if not isinstance(selected, dict):
            return False
        return selected.get("answers") == [APPROVAL_ANSWER]

    def approve_from_tool(self, payload: dict[str, Any]) -> bool:
        if str(payload.get("tool_name") or "").lower() != "request_user_input":
            return False
        with self._locked():
            return self._approve_from_tool_locked(payload)

    def _approve_from_tool_locked(self, payload: dict[str, Any]) -> bool:
        session_id, turn_id = self._scope(payload)
        input_hash = _digest(payload.get("tool_input") or {})
        now = time.time()
        if not self.pending.exists():
            return False
        candidates = sorted(self.pending.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for target in candidates:
            record = self._read(target)
            if record is None:
                continue
            if (
                record.get("session_id") != session_id
                or record.get("turn_id") != turn_id
                or record.get("approval_input_hash") != input_hash
                or record.get("expires_at", 0) <= now
                or record.get("consumed_at")
            ):
                continue
            record["consumed_at"] = now
            self._write(target, record)
            if not self._approved_answer(payload.get("tool_response")):
                return False
            receipt_id = secrets.token_urlsafe(18)
            receipt = {
                "id": receipt_id,
                "session_id": session_id,
                "turn_id": turn_id,
                "fingerprint": record["fingerprint"],
                "consequence": record["consequence"],
                "issued_at": now,
                "expires_at": now + self.ttl_seconds,
            }
            self._write(self.approved / f"{receipt_id}.json", receipt)
            return True
        return False

    def consume_approval(self, payload: dict[str, Any]) -> bool:
        with self._locked():
            return self._consume_approval_locked(payload)

    def _consume_approval_locked(self, payload: dict[str, Any]) -> bool:
        session_id, turn_id = self._scope(payload)
        fingerprint = self.action_fingerprint(payload)
        now = time.time()
        if not self.approved.exists():
            return False
        candidates = sorted(self.approved.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for target in candidates:
            record = self._read(target)
            if record is None:
                continue
            if (
                record.get("session_id") != session_id
                or record.get("turn_id") != turn_id
                or record.get("fingerprint") != fingerprint
                or record.get("expires_at", 0) <= now
                or record.get("consumed_at")
            ):
                continue
            record["consumed_at"] = now
            self._write(target, record)
            return True
        return False
