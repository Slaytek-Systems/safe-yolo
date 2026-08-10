from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from adapters.codex import WRITE_TOOLS, append_audit_record, candidate_write_paths, evaluate_payload, request_context
from engine.capabilities import CapabilityStore, PendingMaintenanceStore
from engine.recovery import FileCheckpointStore, RecoveryUnavailable
from engine.safe_yolo import SafeYoloEngine, result


WRITE_NAMES = {"write", "strreplace", "editnotebook", "edit_notebook"}
DELETE_NAMES = {"delete"}
READ_NAMES = {"read", "grep", "glob", "readdir", "list_dir", "listdir", "semsearch", "read_lints", "readlints"}
SHELL_NAMES = {"shell", "bash"}
ALLOW_NAMES = {
    "task",
    "todowrite",
    "todo_write",
    "await",
    "awaitshell",
    "switchmode",
    "generateimage",
    "websearch",
    "webfetch",
    "searchconversations",
    "fetchmcpresource",
    "getmcptools",
    "callmcptool",
}


def _load_stdin() -> dict[str, Any]:
    raw = sys.stdin.buffer.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8").lstrip("\ufeff")
    payload = json.loads(text) if text.strip() else {}
    if not isinstance(payload, dict):
        raise ValueError("Cursor hook payload must be a JSON object.")
    return payload


def normalize_identity(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    conversation_id = str(payload.get("conversation_id") or payload.get("session_id") or "")
    generation_id = str(payload.get("generation_id") or payload.get("turn_id") or "")
    if conversation_id:
        normalized["session_id"] = conversation_id
    if generation_id:
        normalized["turn_id"] = generation_id
    return normalized


def normalize_tool_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Map Cursor hook events onto the shared Codex evaluation shape."""
    normalized = normalize_identity(payload)
    event = str(payload.get("hook_event_name") or "").strip()

    if event == "beforeShellExecution" or (
        event != "beforeMCPExecution" and "command" in payload and "tool_name" not in payload
    ):
        command = payload.get("command") or ""
        cwd = payload.get("cwd") or ""
        tool_input: dict[str, Any] = {"command": command}
        if isinstance(cwd, str) and cwd:
            tool_input["workdir"] = cwd
            normalized["cwd"] = cwd
        normalized["tool_name"] = "Shell"
        normalized["tool_input"] = tool_input
        return normalized

    if event == "beforeReadFile":
        path = payload.get("file_path") or payload.get("path") or ""
        normalized["tool_name"] = "Read"
        normalized["tool_input"] = {"path": path}
        return normalized

    if event == "beforeMCPExecution":
        tool_name = str(payload.get("tool_name") or "mcp")
        tool_input = payload.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except json.JSONDecodeError:
                tool_input = {"raw": tool_input}
        normalized["tool_name"] = tool_name
        normalized["tool_input"] = tool_input if isinstance(tool_input, dict) else {"value": tool_input}
        return normalized

    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    lower = tool_name.lower()
    mapped_input = dict(tool_input)
    if lower in {"editnotebook", "edit_notebook"} and "path" not in mapped_input:
        notebook = mapped_input.get("target_notebook") or mapped_input.get("notebook_path")
        if isinstance(notebook, str) and notebook:
            mapped_input["path"] = notebook

    if lower == "strreplace" or lower in {"editnotebook", "edit_notebook"}:
        mapped_name = "Write"
    elif lower == "delete":
        mapped_name = "delete_file"
    elif lower == "shell":
        mapped_name = "Shell"
    else:
        mapped_name = tool_name or "Unknown"

    working_directory = mapped_input.get("working_directory")
    if isinstance(working_directory, str) and working_directory:
        normalized.setdefault("cwd", working_directory)
        mapped_input.setdefault("workdir", working_directory)

    normalized["tool_name"] = mapped_name
    normalized["tool_input"] = mapped_input
    return normalized


def evaluate_cursor_payload(payload: dict[str, Any], engine: SafeYoloEngine) -> dict[str, Any]:
    normalized = normalize_tool_payload(payload)
    tool_name = str(normalized.get("tool_name") or "").lower()
    original = str(payload.get("tool_name") or "").lower()
    event = str(payload.get("hook_event_name") or "")

    if event == "beforeMCPExecution":
        return result(
            "block_method",
            "tool.unclassified",
            "Cursor MCP execution requires an explicit consequence mapping before use.",
        )

    if original in ALLOW_NAMES or tool_name in ALLOW_NAMES:
        return result("allow", "cursor.passthrough", "Non-mutating tool orchestration is permitted.")

    if tool_name in READ_NAMES or original in READ_NAMES:
        tool_input = normalized.get("tool_input") or {}
        path = ""
        if isinstance(tool_input, dict):
            path = str(tool_input.get("path") or tool_input.get("file_path") or "")
        if path:
            rule = engine._protected_rule(path, normalized.get("cwd"))
            if rule is not None and rule.get("action") in {"credentials.expose", "credentials.read"}:
                context = {key: normalized[key] for key in ("session_id", "cwd") if key in normalized}
                return engine.evaluate({"action": rule["action"], **context})
        return result("allow", "cursor.read", "Ordinary read/search is permitted.")

    if tool_name in DELETE_NAMES or original in DELETE_NAMES or tool_name == "delete_file":
        normalized["tool_name"] = "delete_file"
        return evaluate_payload(normalized, engine)

    if original in WRITE_NAMES or tool_name == "write":
        normalized["tool_name"] = "Write"
        return evaluate_payload(normalized, engine)

    if tool_name in SHELL_NAMES or original in SHELL_NAMES:
        normalized["tool_name"] = "Shell"
        return evaluate_payload(normalized, engine)

    return evaluate_payload(normalized, engine)


def cursor_hook_response(
    decision: dict[str, Any],
    *,
    pending: dict[str, Any] | None = None,
    event: str = "",
) -> dict[str, Any]:
    if decision["decision"] not in {"block_hard", "block_method", "require_capability"}:
        if event == "beforeSubmitPrompt":
            return {"continue": True}
        return {"permission": "allow"}

    reason = f"Safe YOLO [{decision['policy_id']}]: {decision['reason']}"
    if pending is not None:
        scopes = ", ".join(pending.get("scopes") or [])
        harness = pending.get("harness") or "unknown"
        reason += (
            f" Pending request: {harness} ({scopes}). "
            "Reply only yes/approve to authorize; any other reply cancels it."
        )

    if event == "beforeSubmitPrompt":
        return {"continue": False, "user_message": reason}

    return {
        "permission": "deny",
        "user_message": reason,
        "agent_message": reason,
    }


def process_cursor_payload(
    payload: dict[str, Any],
    engine: SafeYoloEngine,
    *,
    pending_store: PendingMaintenanceStore | None = None,
    audit_log: Path | None = None,
    recovery_store: FileCheckpointStore | None = None,
) -> dict[str, Any]:
    event = str(payload.get("hook_event_name") or "")
    normalized = normalize_tool_payload(payload)
    decision = evaluate_cursor_payload(payload, engine)
    if recovery_store is not None and decision["decision"] in {"allow", "allow_report"}:
        tool_name = str(normalized.get("tool_name") or "").lower()
        if tool_name in WRITE_TOOLS:
            context = request_context(normalized)
            cwd = context.get("cwd")
            try:
                if not isinstance(cwd, str) or not cwd:
                    raise RecoveryUnavailable("Structured write requires a known working directory.")
                checkpoint = recovery_store.checkpoint(
                    candidate_write_paths(normalized.get("tool_input") or {}),
                    cwd=cwd,
                    session_id=str(normalized.get("session_id") or ""),
                    turn_id=str(normalized.get("turn_id") or ""),
                )
                decision = {**decision, "recovery_id": checkpoint["id"]}
            except (OSError, ValueError, RecoveryUnavailable) as error:
                decision = result(
                    "block_method",
                    "recovery.unavailable",
                    f"Structured write was not run because its checkpoint failed ({type(error).__name__}).",
                )
    pending = None
    request = decision.get("maintenance_request")
    session_id = str(normalized.get("session_id") or "")
    if isinstance(request, dict) and pending_store is not None and session_id:
        pending = pending_store.request(
            session_id=session_id,
            harness=str(request["harness"]),
            scopes=list(request["scopes"]),
        )
    if audit_log is not None:
        try:
            append_audit_record(audit_log, normalized, decision)
        except OSError:
            pass
    return cursor_hook_response(decision, pending=pending, event=event)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Authoritative Safe YOLO Cursor adapter.")
    parser.add_argument("--policy", type=Path, default=root / "policy" / "policy.json")
    parser.add_argument(
        "--host-contract",
        type=Path,
        default=Path(os.environ["SAFE_YOLO_HOST_CONTRACT"]).expanduser()
        if os.environ.get("SAFE_YOLO_HOST_CONTRACT")
        else None,
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser(),
    )
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()

    try:
        payload = _load_stdin()
    except (json.JSONDecodeError, ValueError) as error:
        json.dump(
            {
                "permission": "deny",
                "user_message": f"Safe YOLO fail-closed: invalid Cursor hook payload ({error}).",
                "agent_message": f"Safe YOLO fail-closed: invalid Cursor hook payload ({error}).",
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0

    store = CapabilityStore(args.state_dir / "capabilities")
    pending = PendingMaintenanceStore(args.state_dir / "pending-maintenance")
    recovery = FileCheckpointStore(args.state_dir / "recovery")
    host_contract = json.loads(args.host_contract.read_text(encoding="utf-8")) if args.host_contract else None
    engine = SafeYoloEngine.from_file(args.policy, capability_store=store, host_contract=host_contract)

    if args.explain:
        response: dict[str, Any] | None = evaluate_cursor_payload(payload, engine)
    elif args.audit_only:
        decision = evaluate_cursor_payload(payload, engine)
        try:
            append_audit_record(args.state_dir / "audit.jsonl", normalize_tool_payload(payload), decision)
        except OSError:
            pass
        response = None
    else:
        response = process_cursor_payload(
            payload,
            engine,
            pending_store=pending,
            audit_log=args.state_dir / "audit.jsonl",
            recovery_store=recovery,
        )

    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
