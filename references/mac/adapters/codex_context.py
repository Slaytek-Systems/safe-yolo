from __future__ import annotations

from typing import Any


def turn_scope(payload: dict[str, Any]) -> str:
    session_id = str(payload.get("session_id") or "")
    turn_id = str(payload.get("turn_id") or "")
    if session_id and turn_id:
        return f"{session_id}__{turn_id}"
    return session_id
