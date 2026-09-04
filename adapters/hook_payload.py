from __future__ import annotations

from typing import Any


_CAMEL_KEYS = {
    "hookEventName": "hook_event_name",
    "toolName": "tool_name",
    "toolInput": "tool_input",
    "sessionId": "session_id",
    "sessionID": "session_id",
    "toolUseId": "tool_use_id",
    "promptId": "prompt_id",
    "workspaceRoot": "workspace_root",
    "permissionMode": "permission_mode",
    "conversationId": "conversation_id",
    "generationId": "generation_id",
    "workingDirectory": "working_directory",
    "filePath": "file_path",
    "targetFile": "target_file",
    "callID": "call_id",
    "patchText": "patch_text",
    "notebookPath": "notebook_path",
    "targetNotebook": "target_notebook",
}

_NESTED_OBJECTS = {"tool_input", "args"}


def normalize_hook_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a snake_case hook payload, mapping PreToolUse event aliases."""
    if not isinstance(payload, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        dest = _CAMEL_KEYS.get(key, key)
        if dest in _NESTED_OBJECTS and isinstance(value, dict):
            value = _normalize_object(value)
        if dest in normalized and key != dest:
            continue
        normalized[dest] = value
    event = normalized.get("hook_event_name")
    if isinstance(event, str):
        normalized["hook_event_name"] = _normalize_event_name(event)
    return normalized


def _normalize_object(value: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        dest = _CAMEL_KEYS.get(key, key)
        if dest in normalized and key != dest:
            continue
        normalized[dest] = item
    return normalized


def _normalize_event_name(name: str) -> str:
    if name.replace("_", "").lower() == "pretooluse":
        return "PreToolUse"
    return name
