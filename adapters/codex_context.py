from typing import Any


def turn_scope(payload: dict[str, Any]) -> str:
    session_id = str(payload.get("session_id") or "")
    turn_id = str(payload.get("turn_id") or "")
    return f"{session_id}__{turn_id}" if session_id and turn_id else session_id
