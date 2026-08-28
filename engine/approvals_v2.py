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
REJECT_ANSWER = "Reject"
QUESTION_ID = "safe_yolo_approval"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class ApprovalLedger:
    """Host-local, one-shot approvals bound to an exact tool action."""

    def __init__(
        self,
        root: str | Path,
        *,
        pending_ttl_seconds: int = 30 * 60,
        receipt_ttl_seconds: int = 5 * 60,
        ttl_seconds: int | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve(strict=False)
        self.pending = self.root / "pending-v2"
        self.approved = self.root / "approved-v2"
        if ttl_seconds is not None:
            pending_ttl_seconds = ttl_seconds
            receipt_ttl_seconds = ttl_seconds
        self.pending_ttl_seconds = pending_ttl_seconds
        self.receipt_ttl_seconds = receipt_ttl_seconds

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
        fingerprint = self.action_fingerprint(payload)
        now = time.time()
        with self._locked():
            self._prune_locked(now)
            candidates = sorted(
                self.pending.glob("*.json"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            ) if self.pending.exists() else []
            matches: list[tuple[Path, dict[str, Any]]] = []
            for target in candidates:
                record = self._read(target)
                if record is None:
                    continue
                if (
                    record.get("session_id") == session_id
                    and record.get("turn_id") == turn_id
                    and record.get("fingerprint") == fingerprint
                    and record.get("consequence") == consequence
                    and record.get("expires_at", 0) > now
                    and not record.get("consumed_at")
                ):
                    matches.append((target, record))
            if matches:
                _, record = matches[0]
                for duplicate, _ in matches[1:]:
                    duplicate.unlink(missing_ok=True)
                tool_input = self._approval_input(
                    request_id=str(record.get("id") or ""),
                    fingerprint=fingerprint,
                    consequence=consequence,
                    display=display,
                )
                if (
                    not record.get("id")
                    or record.get("approval_input_hash") != _digest(tool_input)
                ):
                    raise ValueError("Pending approval request does not match the current action.")
                return tool_input

            request_id = secrets.token_urlsafe(18)
            tool_input = self._approval_input(
                request_id=request_id,
                fingerprint=fingerprint,
                consequence=consequence,
                display=display,
            )
            record = {
                "id": request_id,
                "session_id": session_id,
                "turn_id": turn_id,
                "fingerprint": fingerprint,
                "consequence": consequence,
                "approval_input_hash": _digest(tool_input),
                "issued_at": now,
                "expires_at": now + self.pending_ttl_seconds,
            }
            self._write(self.pending / f"{request_id}.json", record)
        return tool_input

    @staticmethod
    def _approval_input(
        *,
        request_id: str,
        fingerprint: str,
        consequence: str,
        display: str,
    ) -> dict[str, Any]:
        question = (
            f"Approve one exact retry for {consequence}: {display}? "
            f"Request {request_id}; action fingerprint {fingerprint}."
        )
        return {
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
                            "label": REJECT_ANSWER,
                            "description": "Keep the consequential action blocked.",
                        },
                    ],
                }
            ]
        }

    @staticmethod
    def _approval_answer(response: Any) -> str | None:
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                return None
        if not isinstance(response, dict):
            return None
        answers = response.get("answers")
        if not isinstance(answers, dict):
            return None
        selected = answers.get(QUESTION_ID)
        if not isinstance(selected, dict):
            return None
        values = selected.get("answers")
        if values == [APPROVAL_ANSWER]:
            return APPROVAL_ANSWER
        if values == [REJECT_ANSWER]:
            return REJECT_ANSWER
        return None

    def approve_from_tool(self, payload: dict[str, Any]) -> bool:
        if str(payload.get("tool_name") or "").lower() != "request_user_input":
            return False
        with self._locked():
            return self._approve_from_tool_locked(payload)

    def _approve_from_tool_locked(self, payload: dict[str, Any]) -> bool:
        session_id, turn_id = self._scope(payload)
        input_hash = _digest(payload.get("tool_input") or {})
        now = time.time()
        self._prune_locked(now)
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
            answer = self._approval_answer(payload.get("tool_response"))
            if answer is None:
                return False
            self._close_action_requests_locked(record)
            if answer != APPROVAL_ANSWER:
                return False
            receipt_id = secrets.token_urlsafe(18)
            receipt = {
                "id": receipt_id,
                "session_id": session_id,
                "turn_id": turn_id,
                "fingerprint": record["fingerprint"],
                "consequence": record["consequence"],
                "issued_at": now,
                "expires_at": now + self.receipt_ttl_seconds,
            }
            self._write(self.approved / f"{receipt_id}.json", receipt)
            return True
        return False

    def _close_action_requests_locked(self, selected: dict[str, Any]) -> None:
        if not self.pending.exists():
            return
        for target in self.pending.glob("*.json"):
            record = self._read(target)
            if record is None:
                continue
            if (
                record.get("session_id") == selected.get("session_id")
                and record.get("turn_id") == selected.get("turn_id")
                and record.get("fingerprint") == selected.get("fingerprint")
            ):
                target.unlink(missing_ok=True)

    def consume_approval(self, payload: dict[str, Any]) -> bool:
        with self._locked():
            return self._consume_approval_locked(payload)

    def _consume_approval_locked(self, payload: dict[str, Any]) -> bool:
        session_id, turn_id = self._scope(payload)
        fingerprint = self.action_fingerprint(payload)
        now = time.time()
        self._prune_locked(now)
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
            target.unlink(missing_ok=True)
            return True
        return False

    def _prune_locked(self, now: float) -> None:
        for directory in (self.pending, self.approved):
            if not directory.exists():
                continue
            for target in directory.glob("*.json"):
                record = self._read(target)
                if (
                    record is None
                    or record.get("consumed_at")
                    or record.get("expires_at", 0) <= now
                ):
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        continue
